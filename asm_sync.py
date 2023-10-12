import json
import os
import pandas as pd
import requests
import time
from tenable.io import TenableIO
from dotenv import load_dotenv


load_dotenv()

JOB_POLL = os.getenv('JOB_POLL', 5)

TENB_ASM_TOKEN = os.getenv('TENB_ASM_TOKEN')
SP_ASM_TOKEN = os.getenv('SP_ASM_TOKEN')
BB_ASM_TOKEN = os.getenv('BB_ASM_TOKEN')



inventory_columns = [
    'bd.ip_address', 'ports.ports', 'bd.original_hostname', 'bd.host', 'screenshot.finalurl', 
    'ports.services', 'ports.banners', 'ipgeo.asn'
]

keyword_tags = ['Scan Name']
inventory_tags = ['ipgeo.asn']


class ASM:
    def __init__(self, asm_token):
        self.asm_token = asm_token
        self.inventory_url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventory' 
        self.tags_url = 'https://asm-demo.cloud.tenable.com/api/1.0/tags'

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
        
    def create_tag_lookup(self):
        '''create lookup table to translate keyword tag column names (tag_<id>_keyword) to readable name'''
        headers = {'accept': 'application/json', 'Authorization': self.asm_token}
        response = requests.get(self.tags_url, headers=headers)
        asm_tags =  response.json()
        # tag_tuples = [(f'bd.tag_{tag["id"]}_keyword', tag["name"]) for tag in asm_tags if tag['name'] in allow_tags]
        return dict([(f'bd.tag_{tag["id"]}_keyword', tag["name"]) for tag in asm_tags if tag['name'] in keyword_tags])

    def get_asm_inventory_records(self):    
        # get ASM keyword tags to include in the inventory columns
        tags = self.get_asm_tags()
        tag_columns = [f'bd.tag_{tag["id"]}_keyword' for tag in tags if tag['value_type'] == 'keyword']
    
        # combine column names with tag names to include in the inventory query
        column_list = ','.join(inventory_columns + tag_columns)
        
        a_records= [
            {'column': 'bd.record_type', 'type': 'is', 'value': 'A'}
        ]

        inventory = self.get_inventory(column_list, offset=0, limit=5000, filters=a_records) 

        asm_data = pd.DataFrame.from_records(inventory['assets'])
        columns = keyword_tags + ['bd.ip_address']

        # create lookup dict for renaming tag columns to readable tag names (from bd.tag_<ID>_keyword) 
        tag_names = self.create_tag_lookup()
        try:
            asm_data = asm_data.rename(columns=tag_names)[columns]
        except KeyError as e:
            print(f'{str(e)} keyword tag not defined in ASM data')
        return asm_data

    # def get_asm_tagged_a_records(self) -> pd.DataFrame:
    #     # create lookup dict for renaming tag columns to readable tag names (from bd.tag_<ID>_keyword) 
    #     tags_by_id = self.create_tag_lookup()
    #     inventory = self.get_asm_inventory_records()
    #     asm_data = pd.DataFrame.from_records(inventory['assets'])
    #     columns = allow_tags + ['bd.ip_address']
    #     try:
    #         asm_data = asm_data.rename(columns=tags_by_id)[columns]
    #     except KeyError as e:
    #         print(f'{str(e)} keyword tags missing in ASM data')
    #     return asm_data

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
    
    def asset_uuids(self) -> dict:
        '''export and filter assets with the specified source, return dict[ip] = uuid'''
        return {asset['ipv4s'][0]: asset['id'] for asset in self.tio.exports.assets(sources=[self.source])}

    def import_discovered_assets(self, asm_df):
        discovered_ips = asm_df[asm_df['uuid'].isna()]['bd.ip_address']
        print(f'importing {len(discovered_ips)} ASM assets not found TVM ...')
        # parse inventory records into asset import format
        # asset_records = [transform_parameters(record) for record in assets]
        asset_records = list(self.map_parameters(discovered_ips))
    
        tio = TenableIO()
        job_id = tio.assets.asset_import(self.source, *asset_records)
        print(f"importing {len(asset_records)} assets job id: {job_id}")
    
        while True:
            # poll for status until job complete
            job = tio.assets.import_job_details(job_id)
            if job['status'] == 'COMPLETE':
                print(f'import complete for job id: {job_id}')
                print(job)
                break
            time.sleep(JOB_POLL)
        return job
        
    def tag_uuids(self, category, values):
        '''get tag uuid for each category value, create tag if it does not exist'''
        tag_name_lookup = {tag['value']: tag['uuid'] for tag in self.tio.tags.list(('category_name', 'eq', category))}
        for value in values:
            if value not in tag_name_lookup:
                print(f'creating tag {value}')
                tag = self.tio.tags.create(category, value)
                tag_name_lookup[value] = tag['uuid']
        return tag_name_lookup

    def update_tags(self, asm_df):
        ''' this needs to be reworked to apply more than one tag_value at a time'''
        asm_attributes = keyword_tags + inventory_tags
        for tag_category in keyword_tags:
            # get a list of unique values for this category
            tag_values = asm_df[tag_category].unique()
            # get a dictionary to translate tag_value to tio tag_uuid, tags are created if needed
            tag_uuid_lookup = self.tag_uuids(tag_category, tag_values)
    
            # for each tag value
            for tag_value in tag_values:
                # get asset_uuids matching this tag value
                df = asm_df[asm_df[tag_category] == tag_value]
                asset_uuids = list(df.uuid)
                tag_uuid = tag_uuid_lookup[tag_value]
                self.tio.tags.assign(asset_uuids, [tag_uuid])
                
                print('tag_uuid', tag_uuid)
                print(f'tagging {len(df.uuid)} assets with {tag_category}:{tag_value}')
                self.tio.tags.assign(asset_uuids, [tag_uuid])


def correlate_records():

        tvm = TVM(tio=TenableIO(), source='SPartners')
        asm = ASM(asm_token=SP_ASM_TOKEN)

        asm_df = asm.get_asm_tagged_a_records()
    
        uuid_lookup = tvm.asset_uuids()
        
        # inject a tenable uuid for each IP address in the ASM DataFrame
        asm_df['uuid'] = asm_df['bd.ip_address'].map(lambda ip: uuid_lookup.get(ip))
    
        # import any ASM records that have not been assigned a tenable UUID (not yet scanned)
        tvm.import_discovered_assets(asm_df)

        



        matching_uuids = asm_df[~asm_df['uuid'].isna()]['bd.ip_address']
        print(f'{len(matching_uuids)} ASM IPs with an asset uuid')
        return asm_df


if __name__ == "__main__":
    correlate_records()
