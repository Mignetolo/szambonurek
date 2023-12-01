import pyshark
import re
from openpyxl import Workbook
import hashlib

# Function to initialize regular expressions
def initialize_regex():
    regex_dict = {
        'IPv4': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        'IPv6': re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
        'Email': re.compile(r'\S+@\S+'),
        'Domain Name': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b(?![\d.])'),
    }
    return regex_dict

# Function to save packet data to a sheet
def save_packet_data(sheet, packet):
    packet_info = [packet.number, packet.sniff_timestamp, packet.length, packet.transport_layer]
    sheet.append(packet_info)

# Function to process packets and match regex patterns
def process_packets(cap, regex_dict, workbook):
    summary_dict = {}
    packet_counter = 1

    # Create summary sheet first
    summary_sheet = workbook.create_sheet(title='Summary')
    summary_sheet.append(['Match Type', 'Match Value', 'Count', 'Packet Numbers'])

    for packet in cap:
        packet_data = str(packet)
        packet_saved = False

        for regex_name, regex_pattern in regex_dict.items():
            matches = regex_pattern.findall(packet_data)
            if matches:
                if not packet_saved:
                    packet_saved = True
                    sheet_name = f'Packet_{packet_counter}'
                    sheet = workbook.create_sheet(title=sheet_name)
                    sheet.append(['Packet Number', 'Time', 'Length', 'Transport Layer'])
                    save_packet_data(sheet, packet)

                data_sheet = workbook[sheet_name]
                data_sheet.append([f'{regex_name} Match'])
                for match in matches:
                    data_sheet.append([match])

                    # Update summary dictionary
                    if regex_name in summary_dict:
                        if match in summary_dict[regex_name]:
                            summary_dict[regex_name][match]['count'] += 1
                            summary_dict[regex_name][match]['packets'].append(packet_counter)
                        else:
                            summary_dict[regex_name][match] = {'count': 1, 'packets': [packet_counter]}
                    else:
                        summary_dict[regex_name] = {match: {'count': 1, 'packets': [packet_counter]}}

        packet_counter += 1

    # Populate summary sheet with unique matches, count, and packet numbers
    for regex_name, matches in summary_dict.items():
        for match, data in matches.items():
            packet_numbers = ', '.join(map(str, data['packets']))
            summary_sheet.append([regex_name, match, data['count'], packet_numbers])

    return workbook

# Function to calculate file hash
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hasher.update(chunk)
    file_hash = hasher.hexdigest()
    return file_hash

def run_process(file_path, output_file):
    print(f"Hash pliku Excela ({file_path}): {calculate_file_hash(file_path)}")
    cap = pyshark.FileCapture(file_path)
    regex_dict = initialize_regex()
    workbook = Workbook()
    workbook = process_packets(cap, regex_dict, workbook)
    workbook.remove(workbook['Sheet'])
    workbook.save(output_file)
    cap.close()
    print(f"Hash pliku Excela ({output_file}): {calculate_file_hash(output_file)}")

file_path = ''
output_file =file_path[:-5]+'_output.xlsx'
run_process(file_path, output_file)
