import os
import requests

from tenable.io import TenableIO
from dotenv import load_dotenv
from pprint import pprint

load_dotenv()

ASM_TOKEN = os.getenv('ASM_TOKEN')

inventory_columns = [
    'bd.record_type', 
    'bd.ip_address', 
    'ipgeo.asn', 
    'ports.ports', 
    'bd.tags', 
    'bd.original_hostname', 
    'screenshot.screenshot', 
    'ports.services', 
    'ports.lastseen'
]


def get_asm_tags() -> list[dict]:
    '''get a list of tags and return the id for tag with name'''
    tags_url = 'https://asm-demo.cloud.tenable.com/api/1.0/tags'
    headers = {'accept': 'application/json', 'Authorization': ASM_TOKEN}
    response = requests.get(tags_url, headers=headers)
    return response.json()


def get_inventory(columns,  offset=0, limit=50) -> dict:
    '''filter inventory by tag'''
    # tag_id = get_tag_id(tag_name)
    # tag_str = f'bd.tag_{tag_id}_keyword'

    inventory_url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventory' 
    url_params = f'offset={offset}&limit={limit}&sortorder=true&columns={columns}&inventory=false'
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': ASM_TOKEN}
    # payload = [
        # {'column': tag_str, 'type': operator, 'value': tag_value, 'endLabel': '', 'readOnly': False}
    # ]
    response = requests.post(f'{inventory_url}?{url_params}', headers=headers)
    return response.json()


def main():
    tags = get_asm_tags()
    tag_columns = [f'bd.tag_{tag["id"]}_keyword' for tag in tags if tag['value_type'] == 'keyword']
    columns = ','.join(inventory_columns + tag_columns)
    pprint(tags)
    inventory = get_inventory(columns) 
    pprint(inventory)


if __name__ == '__main__':
    main()

