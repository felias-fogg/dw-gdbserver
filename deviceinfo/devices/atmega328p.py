"""
Required device info for the ATmega328P device
"""
from pymcuprog.deviceinfo.eraseflags import ChiperaseEffect

DEVICE_INFO = {
    'name': 'atmega328p',
    'architecture': 'avr8',

    # Flash
    'flash_address_byte': 0,
    'flash_size_bytes': 0x8000,
    'flash_page_size_bytes': 0x80,
    'flash_write_size_bytes': 0x80,
    'flash_read_size_bytes': 0x80,
    'flash_chiperase_effect': ChiperaseEffect.ALWAYS_ERASED,
    'flash_isolated_erase': False,

    # signatures
    'signatures_address_byte': 0,
    'signatures_size_bytes': 3,
    'signatures_page_size_bytes': 1,
    'signatures_read_size_bytes': 1,
    'signatures_write_size_bytes': 0,
    'signatures_chiperase_effect': ChiperaseEffect.NOT_ERASED,
    'signatures_isolated_erase': False,

    # calibration
    'calibration_row_address_byte': 0,
    'calibration_row_size_bytes': 1,
    'calibration_row_page_size_bytes': 1,
    'calibration_row_read_size_bytes': 1,
    'calibration_row_write_size_bytes': 1,
    'calibration_row_chiperase_effect': ChiperaseEffect.NOT_ERASED,
    'calibration_row_isolated_erase': False,

    # fuses
    'fuses_address_byte': 0,
    'fuses_size_bytes': 0x0003,
    'fuses_page_size_bytes': 1,
    'fuses_read_size_bytes': 1,
    'fuses_write_size_bytes': 1,
    'fuses_chiperase_effect': ChiperaseEffect.NOT_ERASED,
    'fuses_isolated_erase': False,

    # internal_sram
    'internal_sram_address_byte': 0x0100, 
    'internal_sram_size_bytes': 0x0800, 
    'internal_sram_page_size_bytes': 0x01,
    'internal_sram_read_size_bytes': 0x01,
    'internal_sram_write_size_bytes': 0x01,
    'internal_sram_chiperase_effect': ChiperaseEffect.NOT_ERASED,
    'internal_sram_isolated_erase': False,

    # lockbits
    'lockbits_address_byte': 0,
    'lockbits_size_bytes': 0x0001,
    'lockbits_page_size_bytes': 1,
    'lockbits_write_size_bytes': 1,
    'lockbits_read_size_bytes': 1,
    'lockbits_chiperase_effect': ChiperaseEffect.ALWAYS_ERASED,
    'lockbits_isolated_erase': False,

    # eeprom
    'eeprom_address_byte': 0x0000,
    'eeprom_size_bytes': 0x0400,
    'eeprom_page_size_bytes': 0x04,
    'eeprom_read_size_bytes': 1,
    'eeprom_write_size_bytes': 1,
    'eeprom_chiperase_effect': ChiperaseEffect.CONDITIONALLY_ERASED_AVR,
    'eeprom_isolated_erase': False,

    # Some extra specific fields for debugWIRE MCUs
    'ocd_base' : 0x31,
    'ocd_rev' : 0x01,
    'eearh_base' : 0x22,
    'eearl_base' : 0x21,
    'eecr_base' : 0x1F,
    'eedr_base' : 0x20,
    'spmcr_base' : 0x57,
    'osccal_base' : 0x66,
    'dwen_fusebit' : 0x40, # always high fuse
    'bootrst_fuse': 1, # it is bit 0 of the high fuse 
    'interface': 'ISP+DW',
    'device_id': 0x1E950F,
}
