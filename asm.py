import os
import pandas as pd
import requests


# def remove_commas(df: pd.DataFrame, columns: list):
#     '''remove commas from values in specified columns'''
#     for column in columns:
#         # replace nan with empty string replace commas with spaces
#         df[column] = df[column].fillna('').map(lambda x: x.replace(',', ' '))


class ASM:
    def __init__(self, columns, asm_token=os.getenv('ASM_TOKEN'), limit=50):
        if asm_token is None:
            raise ValueError('ASM_TOKEN environment variable not set')
        self.inventory_columns = columns
        self.asm_token = asm_token
        self.limit = limit
        self.inventory_url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventory' 
        self.tags_url = 'https://asm-demo.cloud.tenable.com/api/1.0/tags'
        
        self.tag_index = self._init_tags()
        self.inventory = self.get_asm_inventory_records()

    def _init_tags(self):
        headers = {'accept': 'application/json', 'Authorization': self.asm_token}
        response = requests.get(self.tags_url, headers=headers)
        tags = response.json()
        return {f'bd.tag_{tag["id"]}_keyword': tag['name'] for tag in tags if tag['value_type'] == 'keyword'}
        
    # def get_asm_tags(self) -> list[dict]:
        # '''get a list of tags and return the id for tag with name'''
        # headers = {'accept': 'application/json', 'Authorization': self.asm_token}
        # response = requests.get(self.tags_url, headers=headers)
        # return response.json()

    def get_inventory(self, columns, offset=0, limit=10, filters=None) -> dict:
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
        column_list = ','.join(set(self.inventory_columns) | set(self.tag_index.values()))
        print(f'column_list: {column_list}')

        inventory = self.get_inventory(column_list, offset=0, limit=limit, filters=record_filter) 

        # load dataframe and rename the tag columns to readable name
        df = pd.DataFrame.from_records(inventory['assets']).rename(columns=self.tag_index)
        print(f'column_list: {column_list}\n')
        print(f'df columns: {list(df)}')

        # replace any commas in keyword_tag values with an empty string
        for column in set(self.tag_index.values()):
            if column in df.columns:
                df[column] = df[column].fillna('').map(lambda x: x.replace(',', ' '))
            else:
                print("ASM records have no data in column: {column}")

        return df