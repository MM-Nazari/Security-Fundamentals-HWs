import argparse
import inspect
import socket
import os
import ipaddress
import subprocess


def create_file():
    path = 'C:/Part01-Report.txt'
    f = open(r"C:\Part01-Report.txt", "w")
    f.close()


# Part 01

# create a function to check if an IP address is reachable
def ping(ip):
    output = os.popen("ping -c 4 " + ip).read()
    if ("Request timed out." or "unreachable") in output:
        return False
    else:
        return True


# loop through the IP range and check if each IP is reachable
def scan_ip(start_ip, end_ip, subnetmask):
    create_file()
    print(f"IP range scan report for range from {start_ip} to {end_ip} with subnetmask = {subnetmask}:")
    write_file(f"\nIP range scan report for range from {start_ip} to {end_ip} with subnetmask = {subnetmask}:\n")
    for ip in ipaddress.IPv4Network(start_ip + '/' + str(subnetmask)):
        if ip != ipaddress.IPv4Address(str(ipaddress.IPv4Address(end_ip) + 1)):
            if ping(str(ip)):
                print(str(ip) + " is reachable.")
                write_file(str(ip) + " is reachable.\n")

            else:
                print(str(ip) + " is NOT reachable.")
                write_file(str(ip) + " is NOT reachable.\n")
        else:
            break


# part 02

def get_open_port(start_port, end_port, target_ip, protocol):
    create_file()
    print(
        f"Port range scan from {start_port} to {end_port} in ip address = {target_ip} by protocol = {protocol} report:")
    write_file(
        f"\nPort range scan from {start_port} to {end_port} in ip address = {target_ip} by protocol = {protocol} report:\n")
    # loop over port range and check if each port is open
    for port in range(start_port, end_port + 1, 1):
        # create a new socket object
        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)

        # check if the port is open
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port} with Protocol {protocol} is open")
            write_file(f"Port {port} with Protocol {protocol} is open\n")
        else:
            print(f"Port {port} with Protocol {protocol} is closed")
            write_file(f"Port {port} with Protocol {protocol} is closed\n")

        sock.close()


# Part 03

def get_running_services(ip_address, port, protocol):
    create_file()
    print(f"Services for ip address = {ip_address} with port number = {port} and protocol = {protocol} report:")
    write_file(f"\nServices for ip address = {ip_address} with port number = {port} and protocol = {protocol} report:\n")
    results = []
    try:
        if protocol == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect((ip_address, port))
        s.shutdown(socket.SHUT_RDWR)
        s.close()
        cmd = 'netstat -ano | findstr :{} | findstr LISTENING'.format(port)
        output = os.popen(cmd).read()
        for line in output.strip().split('\n'):
            parts = line.split()
            pid = parts[-1]
            cmd = 'tasklist /fi "pid eq {}" /fo csv /nh'.format(pid)
            tasklist_output = os.popen(cmd).read()
            process_info = tasklist_output.strip().split(',')
            if len(process_info) > 0:
                process_name = process_info[0].replace('"', '')
                results.append(process_name)
    except:
        pass
    for service in results:
        print(f"service found : {service}")
        write_file(f"service found : {service}\n")


# Part 04

def write_file(message):
    f = open(r"C:\Part01-Report.txt", "a")
    f.write(message)
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(title="subcommand")

    parser_scan_ip = subparsers.add_parser('scan_ip')
    parser_scan_ip.add_argument("-start_ip")
    parser_scan_ip.add_argument("-end_ip")
    parser_scan_ip.add_argument("-subnetmask", type=int)
    parser_scan_ip.set_defaults(func=scan_ip)

    parser_get_open_port = subparsers.add_parser('get_open_port')
    parser_get_open_port.add_argument("-start_port", type=int)
    parser_get_open_port.add_argument("-end_port", type=int)
    parser_get_open_port.add_argument("-target_ip")
    parser_get_open_port.add_argument("-protocol")
    parser_get_open_port.set_defaults(func=get_open_port)

    parser_get_running_services = subparsers.add_parser('get_running_services')
    parser_get_running_services.add_argument("-ip_address")
    parser_get_running_services.add_argument("-port", type=int)
    parser_get_running_services.add_argument("-protocol")
    parser_get_running_services.set_defaults(func=get_running_services)

    args = parser.parse_args()

    arg_spec = inspect.getargspec(args.func)
    if arg_spec.keywords:
        ## convert args to a dictionary
        args_for_func = vars(args)
    else:
        ## get a subset of the dictionary containing just the arguments of func
        args_for_func = {k: getattr(args, k) for k in arg_spec.args}

    args.func(**args_for_func)
