#!/usr/bin/env python
# coding: utf-8

import click
import os
import re
import requests
import json 
import time

from dotenv import load_dotenv
from pprint import pprint
from tenable.io import TenableIO

from asm import ASM
from tvm import TVM

load_dotenv()
tio = TenableIO()

inventory_url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventory' 


def get_inventory_chunk(inventory_token, columns, limit, offset=None, after=None, filters=None):
    _offset = f'offset={offset}'
    _limit = f'limit={limit}'
    _after = f'after={after}'
    _columns = f'columns={columns}'
    # _other = 'sortorder=true&inventory=false'
    if filters is None:
        filters = []

    
    params = [_limit, _columns]
    if offset is not None:
        params.append(_offset)
    if after is not None:
        params.append(_after)

    url_params = '&'.join(params)
    request_headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'Authorization':  inventory_token}

    
    response = requests.post(f'{inventory_url}?{url_params}', headers=request_headers, json=filters)
    result = response.json()
    return result


def get_inventory(inventory_token, columns, chunk_size=5000, filters=None):
    last_id = None
    while True:
        inventory = get_inventory_chunk(inventory_token, columns, limit=chunk_size, after=last_id, filters=None)
        if len(inventory['assets']) == 0:
            break
        last_id = inventory['assets'][-1]['id']
        for asset in inventory['assets']:
            yield asset


def is_valid_ipv4(asset):
    ip_address = asset.get('bd.ip_address')
    if ip_address is None:
        return False
    # return True if not ipv6 address and not loopback
    return True if re.match('.*:', ip_address) is None and ip_address != '127.0.0.1' else False


def import_ipv4_list(source, address_list):
    tio_imports = [{'ipv4': [ipv4]} for ipv4 in address_list]
    job_id = tio.assets.asset_import(source, *tio_imports)
    print(f'importing {len(tio_imports)} ipv4 addresses, job_id: {job_id}')
    while True:
        time.sleep(10)
        job = tio.assets.import_job_details(job_id)
        if job['status'] == 'COMPLETE':
            break
    return job


def get_tio_asset_ips(source):
    has_ip = lambda asset: 'ipv4s' in asset and len(asset['ipv4s']) > 0
    return {asset['ipv4s'][0] for asset in tio.exports.assets(sources=[source]) if has_ip(asset)}


def update_assets(inventory, source, columns):

    # get existing assets in Tenable VM
    print(f'exporting assets from Tenable VM[{source}] for comparison ...') 
    tio_ips = get_tio_asset_ips(source)
    print(f'{len(tio_ips)} assets in Tenable VM[{source}]')

    # get inventory records
    print(f'exporting inventory from ASM[{inventory["inventory_name"]}] ...')
    inventory_token = inventory['api_key']
    asm_records = get_inventory(inventory_token, columns)
    
    # get unique ipv4s
    asm_ipv4s = {record['bd.ip_address'] for record in asm_records if is_valid_ipv4(record)}
    print(f'{len(asm_ipv4s)} unique IPv4 addresses')

    # import a list of ipv4s from ASM that are not yet in TIO
    missing_ipv4s = asm_ipv4s - tio_ips
    if len(missing_ipv4s) > 0:
        print(f'importing {len(missing_ipv4s)} records in ASM not found in TIO')
        job = import_ipv4_list(source, missing_ipv4s)
        pprint(job)
    else:
        print('no new assets to import')


def update_tags(tvm: TVM, asm: ASM, inventory_tags=None, excluded_tags=None):
    '''update TVM assets with ASM tags

    Args: 
        tvm: TVM object
        asm: ASM object
        inventory_tags: list of ASM inventory properties to use as tags
    '''
    if inventory_tags is None:
        inventory_tags = []
    if excluded_tags is None:
        excluded_tags = []

    # inject a tenable uuid for matching IP address in the ASM DataFrame
    uuid_lookup = tvm.asset_ip_uuids()
    asm.inventory['uuid'] = asm.inventory['bd.ip_address'].map(lambda ip: uuid_lookup.get(ip))

    # remove excluded tags from the list of custom keyword tags in ASM
    custom_keyword_tags = set(asm.tag_index.values()) - set(excluded_tags)
    tag_categories = custom_keyword_tags | set(inventory_tags)

    # print(f'keyword tags: {asm.tag_index}')
    # print(f'inventory properties: {inventory_properties}')
    # print(f'excluded tags: {excluded_tags}')
    # print(f'tag categories: {tag_categories}')

    # asm.update_uuid_values(uuid_lookup)
        
    tvm.update_tags(asm.inventory, tag_categories)


def list_inventories(primary_asm_token) -> list[dict]:
        url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventories/list?offset=0&limit=100&sortorder=true&include_suggestion_count=false'
        headers = {'accept': 'application/json', 'Authorization': primary_asm_token}
        response = requests.get(f'{url}', headers=headers)
        inventories = response.json()
        return inventories['list']

# declare as global so we can use this in the command validator
primary_asm_token = os.getenv('ASM_TOKEN')
# if primary_asm_token is None:
#     click.exceptions.ClickException('ASM_TOKEN environment variable not set')
asm_inventories = list_inventories(primary_asm_token)

@click.group()
def cli():
    pass


@cli.command('assets')
@click.option('--inventory', 
              type=click.Choice([inventory['inventory_name'] for inventory in asm_inventories]), 
              help='ASM inventory name')
@click.option('--source', help='Tenable VM source name', default='external')
def sync_assets(inventory, source):

    inventory_index = {inventory['inventory_name']: inventory for inventory in asm_inventories}
    inventory = inventory_index[inventory]

    print(f'syncing ASM inventory: {inventory["inventory_name"]} with Tenable VM[{source}] ...')
    columns = 'bd.original_hostname,bd.host,bd.ip_address,bd.tags,bd.record_type'
    update_assets(inventory, source, columns)


@cli.command('tags')
@click.option('--inventory', 
              type=click.Choice([inventory['inventory_name'] for inventory in asm_inventories]), 
              help='ASM inventory name')
@click.option('--source', help='Tenable VM source name', default='external')
def sync_tags(inventory, source):

    inventory_index = {inventory['inventory_name']: inventory for inventory in asm_inventories}
    inventory = inventory_index[inventory]

    print(f'syncing ASM inventory tags: {inventory["inventory_name"]} with Tenable VM[{source}] ...')
    # columns = 'bd.original_hostname,bd.host,bd.ip_address,bd.tags,bd.record_type'
    columns = ['bd.original_hostname', 'bd.host', 'bd.ip_address', 'bd.tags', 'bd.record_type']

    asm = ASM(columns, inventory['api_key'])
    tvm = TVM(tio=TenableIO(), source=source)
    
    update_tags(tvm, asm)


if __name__ == '__main__':
    cli()

