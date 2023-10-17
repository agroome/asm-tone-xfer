import click
import os
import time
import requests
from dotenv import load_dotenv
from pprint import pprint
from tenable.io import TenableIO
from asm import ASM
from tvm import TVM

load_dotenv()


def correlate_assets(tvm: TVM, asm: ASM, excluded_tags=None):
    inventory_columns = [
        'bd.ip_address', 'ports.ports', 'bd.original_hostname', 'bd.host', 'screenshot.finalurl', 
        'ports.services', 'ports.banners', 'ipgeo.asn'
    ]
    # check for existing assets in TVM
    uuid_lookup = tvm.asset_ip_uuids()
    # inject a tenable uuid for matching IP address in the ASM DataFrame
    asm.inventory['uuid'] = asm.inventory['bd.ip_address'].map(lambda ip: uuid_lookup.get(ip))
    # import discovered assets from ASM not in TVM
    tvm.import_assets(asm.inventory)


def correlate_tags(tvm: TVM, asm: ASM, inventory_tags=None, excluded_tags=None):
    if inventory_tags is None:
        inventory_tags = []
    if excluded_tags is None:
        excluded_tags = []

    # inject a tenable uuid for matching IP address in the ASM DataFrame
    uuid_lookup = tvm.asset_ip_uuids()
    asm.inventory['uuid'] = asm.inventory['bd.ip_address'].map(lambda ip: uuid_lookup.get(ip))

    # combine inventory properties with custom keyword tag names
    custom_keyword_tags = set(asm.tag_index.values()) - set(excluded_tags)
    tag_categories = custom_keyword_tags | set(inventory_tags)

    # print(f'keyword tags: {asm.tag_index}')
    # print(f'inventory properties: {inventory_properties}')
    # print(f'excluded tags: {excluded_tags}')
    # print(f'tag categories: {tag_categories}')

    # asm.update_uuid_values(uuid_lookup)
        
    tvm.update_tags(asm.inventory, tag_categories)



@click.group()
def cli():
    pass

@cli.command()
def list_inventories() -> list[dict]:
        asm_token = os.getenv('PRIMARY_ASM_TOKEN')
        url = 'https://asm-demo.cloud.tenable.com/api/1.0/inventories/list?offset=0&limit=25&sortorder=true&include_suggestion_count=false'
        # url_params = f'offset={offset}&limit={limit}&sortorder=true&sortorder=true&include_suggestion_count=false'
        # url_params = f'?offset=0&limit=25&sortorder=true&include_suggestion_count=false'
        headers = {'accept': 'application/json', 'Authorization': asm_token}
        response = requests.get(f'{url}', headers=headers)
        return response.json()

@cli.command('sync')
@click.argument('tio_source')
@click.option('--limit', default=10000, help='limit the number of assets to import')
def main(tio_source, limit):
    inventory_columns = [
        'bd.ip_address', 'ports.ports', 'bd.original_hostname', 'bd.host'
        # 'bd.ip_address', 'ipgeo.asn', 'ports.ports', 'bd.original_hostname', 'bd.host'
    ]
    # tio_source = 'Blackbaud Inventory Test'
    
    print("downloading ASM inventory ...")
    asm = ASM(inventory_columns, limit=limit)
    tvm = TVM(tio=TenableIO(), source=tio_source)

    print(f'saving {len(asm.inventory)} ASM assets to asm_inventory.csv ...')
    asm.inventory.to_csv('asm_inventory.csv')
    print(f'Correlating ASM assets with Tenable VM[{tio_source}] ...\n')
    correlate_assets(tvm, asm)
    print(f'found matching assets in TIO[{tio_source}]: {len(asm.inventory[~asm.inventory.uuid.isna()])}')
    print(f'importing assets not found in TVM[{tio_source}]: {len(asm.inventory[asm.inventory.uuid.isna()])}\n')
    print("waiting 10 minutes for import to process ...")

    # allow time to process new import
    time.sleep(600)

    print(f'Updating Tenable VM [{tio_source}] with ASM tags...\n')
    correlate_tags(tvm, asm, inventory_tags=['ipgeo.asn'], excluded_tags=['SP-ASM'])

def update_tags(tio_source):
    inventory_columns = [
        'bd.ip_address', 'ipgeo.asn', 'ports.ports', 'bd.original_hostname', 'bd.host'
    ]
    
    print("downloading ASM inventory ...")
    asm = ASM(inventory_columns, limit=10000)
    tvm = TVM(tio=TenableIO(), source=tio_source)
    # correlate_tags(tvm, asm, inventory_tags=['ipgeo.asn'], excluded_tags=['SP-ASM'])
    correlate_tags(tvm, asm, excluded_tags=['SP-ASM'])

if __name__ == "__main__":
    # main()
    # tio_source = 'Blackbaud Inventory Test'
    # update_tags(tio_source='Blackbaud Inventory Test')
    # cli(['sync', 'Blackbaud Inventory Test'])
    cli()
