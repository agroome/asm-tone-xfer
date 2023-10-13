import json
import os
import pandas as pd
import requests
import time
from dotenv import load_dotenv
from pprint import pprint
from tenable.io import TenableIO


load_dotenv()

JOB_POLL = os.getenv('JOB_POLL', 5)

ASM_TOKEN = os.getenv('ASM_TOKEN')

inventory_columns = {
    'bd.ip_address', 'ports.ports', 'bd.original_hostname', 'bd.host', 'screenshot.finalurl', 
    'ports.services', 'ports.banners', 'ipgeo.asn'
}

# keyword_tags = ['Scan Name']
# keyword_tags = []
# inventory_tags = {'ipgeo.asn'}
# excluded_tags = []


class ASM:
    def __init__(self, asm_token, limit=50):
        self.asm_token = asm_token
        self.limit = limit
        self.inventory_url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventory' 
        self.tags_url = 'https://asm-demo.cloud.tenable.com/api/1.0/tags'

        tags = self.get_asm_tags()
        self.tag_index = {f'bd.tag_{tag["id"]}_keyword': tag['name'] for tag in tags if tag['value_type'] == 'keyword'}
        # create a list column names for the inventory request 
        # self.tag_columns = [f'bd.tag_{tag["id"]}_keyword' for tag in tags if tag['value_type'] == 'keyword']
        # make a lookup table to translate tag id to tag name

    def get_asm_tags(self) -> list[dict]:
        '''get a list of tags and return the id for tag with name'''
        headers = {'accept': 'application/json', 'Authorization': self.asm_token}
        response = requests.get(self.tags_url, headers=headers)
        return response.json()

    def get_inventory(self, columns,  offset=0, limit=10, filters=None) -> dict:
        url_params = f'offset={offset}&limit={limit}&sortorder=true&columns={columns}&inventory=false'
        headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': self.asm_token}
        if filters is None:
            filters = []
        response = requests.post(f'{self.inventory_url}?{url_params}', headers=headers, json=filters)
        return response.json()

    def get_asm_inventory_records(self, limit=None):    
        if limit is None:
            limit = self.limit
        record_filter= [
            {'column': 'bd.record_type', 'type': 'is', 'value': 'A'}
        ]
        column_list = ','.join(inventory_columns | set(self.tag_index))
        inventory = self.get_inventory(column_list, offset=0, limit=limit, filters=record_filter) 

        asm_data = pd.DataFrame.from_records(inventory['assets'])
        return asm_data.rename(columns=self.tag_index)


class TVM:
    def __init__(self, tio, source):
        self.tio = tio
        self.source = source
        
    @staticmethod
    def map_parameters(asm_df):
        '''convert inventory records to asset import format'''
        records = asm_df.to_dict(orient='records')
        for record in records:
            if 'bd.ip_address' in record and record['bd.ip_address'] != '127.0.0.1':
                yield {'ipv4': [record['bd.ip_address']]}
    
    def asset_ip_uuids(self) -> dict:
        '''export and filter assets with the specified source, return dict[ip] = uuid'''
        return {asset['ipv4s'][0]: asset['id'] for asset in self.tio.exports.assets(sources=[self.source])}

    def import_assets(self, asm_df):
        now = int(time.time())
        if 'uuid' in asm_df.columns:
            discovered_ips = asm_df[asm_df['uuid'].isna()]
        else:
            discovered_ips = asm_df
        discovered_ips = discovered_ips.groupby('bd.ip_address').first().reset_index()
        discovered_ips.to_csv(f'{now}_discovered_ips.csv')

        asset_records = list(self.map_parameters(discovered_ips))

        if len(asset_records) == 0:
            print('no new ASM assets to import')
            return

        print(f'importing {len(asset_records)} ASM assets not found TVM ...')
    
        job_id = self.tio.assets.asset_import(self.source, *asset_records)
    
        while True:
            # poll for status until job complete
            job = self.tio.assets.import_job_details(job_id)
            if job['status'] == 'COMPLETE':
                print(f'import complete for job id: {job_id}')
                pprint(job)
                break
            time.sleep(JOB_POLL)
        return job
        
    def tag_name_uuids(self, category, values):
        '''get tag uuid for each category value, create tag if it does not exist'''
        tag_name_lookup = {tag['value']: tag['uuid'] for tag in self.tio.tags.list(('category_name', 'eq', category))}
        for value in values:
            if value not in tag_name_lookup:
                print(f'creating tag {value}')
                tag = self.tio.tags.create(category, value)
                tag_name_lookup[value] = tag['uuid']
        return tag_name_lookup

    def update_tags(self, asm_df, tag_categories):
        ''' update tags present in asm_df except for exluded_tags if specified'''
        for column in tag_categories:
            # replace nan with empty string replace commas with spaces
            asm_df[column] = asm_df[column].fillna('').map(lambda x: x.replace(',', ' '))

        for tag_category in tag_categories:
            # if tag_category in excluded_tags:
                # continue
            # create a 'non_empty' mask to filter out empty values
            non_empty = asm_df[tag_category] != ''
            tag_values = asm_df[non_empty][tag_category].unique()
            # get a dictionary to translate tag_value to tio tag_uuid, tags are created if needed
            tag_uuid_lookup = self.tag_name_uuids(tag_category, tag_values)
    
            # for each tag value
            for tag_value in tag_values:
                # get asset_uuids matching this tag value
                this_tag = asm_df[tag_category] == tag_value
                asset_uuids = list(asm_df[this_tag].uuid)
                tag_uuid = tag_uuid_lookup[tag_value]
                print(f'applying tag {tag_category}:{tag_value} to {len(asset_uuids)} assets')
                self.tio.tags.assign(asset_uuids, [tag_uuid])


def correlate_assets(tvm, asm, excluded_tags=None):
    asm_df = asm.get_asm_inventory_records()
    
    # check for existing assets in TVM
    uuid_lookup = tvm.asset_ip_uuids()
    # inject a tenable uuid for matching IP address in the ASM DataFrame
    asm_df['uuid'] = asm_df['bd.ip_address'].map(lambda ip: uuid_lookup.get(ip))

    # import discovered assets from ASM not in TVM
    tvm.import_assets(asm_df)
    return asm_df


def correlate_tags(tvm, asm, asm_df, inventory_properties=None, excluded_tags=None):
    if inventory_properties is None:
        inventory_properties = []
    if excluded_tags is None:
        excluded_tags = []

    # combine inventory properties with custom keyword tag names
    tag_categories = (set(asm.tag_index.values()) | set(inventory_properties)) - set(excluded_tags)
    print(f'keyword tags: {asm.tag_index}')
    print(f'inventory properties: {inventory_properties}')
    print(f'excluded tags: {excluded_tags}')
    print(f'tag categories: {tag_categories}')

    uuid_lookup = tvm.asset_ip_uuids()
        
    # inject a tenable uuid for matching IP address in the ASM DataFrame
    asm_df['uuid'] = asm_df['bd.ip_address'].map(lambda ip: uuid_lookup.get(ip))

    tvm.update_tags(asm_df, tag_categories)

    
    # matching_uuids = asm_df[~asm_df['uuid'].isna()]['bd.ip_address']
    # print(f'{len(matching_uuids)} ASM IPs with an asset uuid')

    # return asm_df


def remove_commas(df: pd.DataFrame, columns: list):
    '''remove commas from values in specified columns'''
    for column in columns:
        # replace nan with empty string replace commas with spaces
        df[column] = df[column].fillna('').map(lambda x: x.replace(',', ' '))


def main():

        tvm = TVM(tio=TenableIO(), source='spsource_new')
        asm = ASM(asm_token=ASM_TOKEN, limit=500)

        asm_df = correlate_assets(tvm, asm)
        print(f'ASM assets: {len(asm_df)}')
        print(f'found in TIO: {len(asm_df[~asm_df.uuid.isna()])}')
        print(f'not found in TIO: {len(asm_df[asm_df.uuid.isna()])}')

        # allow time to process new import
        # time.sleep(600)
        correlate_tags(tvm, asm, asm_df, inventory_properties=['ipgeo.asn'], excluded_tags=['SP-ASM'])



# def download_asm(): 
#     asm = ASM(asm_token=ASM_TOKEN)
#     return asm.get_asm_inventory_records()

if __name__ == "__main__":
    main()
