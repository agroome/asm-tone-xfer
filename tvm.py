import os
import time
from pprint import pprint

JOB_POLL = os.getenv('JOB_POLL', 5)


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
        print(f"exporting TVM assets from source: {self.source} ...")
        assets = list(self.tio.exports.assets(sources=[self.source]))
        noip = [asset for asset in assets if 'ipv4s' not in asset or len(asset['ipv4s']) == 0]

        return {asset['ipv4s'][0]: asset['id'] for asset in assets}
        # return {asset['ipv4s'][0]: asset['id'] for asset in self.tio.exports.assets(sources=[self.source])}

    def import_assets(self, asm_df):
        now = int(time.time())
        if 'uuid' in asm_df.columns:
            discovered_ips = asm_df[asm_df['uuid'].isna()]
        else:
            discovered_ips = asm_df
        discovered_ips = discovered_ips.groupby('bd.ip_address').first().reset_index()
        discovered_ips.to_csv(f'{now}_discovered_ips.csv')

        # convert asm records in to asset import format
        asset_records = list(self.map_parameters(discovered_ips))

        if len(asset_records) == 0:
            print('no new ASM assets to import')
            return

        print(f'importing {len(asset_records)} ASM assets not found TVM[{self.source}] ...')
    
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
            if column in asm_df.columns:
                # replace nan values with empty string, replace commas with spaces
                asm_df[column] = asm_df[column].fillna('').map(lambda x: x.replace(',', ' '))

        asm_df.to_csv('asm_df.csv', index=False)
        for tag_category in tag_categories:
            if tag_category not in asm_df.columns:
                # TODO: this could be a custom tag with emptpy values that may require
                # removing tags from TIO
                print(f'no tag values in asm data for {tag_category}')
                continue
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
                # asset_uuids = asm_df[asm_df[this_tag].uuid.notna()].uuid
                asset_uuids = [uuid for uuid in asm_df[this_tag].uuid if uuid is not None]
                if not len(asset_uuids):
                    print(f'no assets found for tag {tag_category}:{tag_value}')
                    continue
                tag_uuid = tag_uuid_lookup[tag_value]
                print(f'applying tag {tag_category}:{tag_value}[{tag_uuid}] to {len(asset_uuids)} assets')
                self.tio.tags.assign(asset_uuids, [tag_uuid])

