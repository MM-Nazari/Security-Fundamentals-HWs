import argparse
import inspect
import nmap


def create_file():
    path = 'C:/Part02-Report.txt'
    f = open(r"C:\Part02-Report.txt", "w")
    f.close()


# Part 01

# Create a function for scanning IP range
def scan_ip(ip_range):
    create_file()
    print(f"IP range scan report for range  {ip_range} :")
    write_file(f"\nIP range scan report for range  {ip_range} :\n")
    scanner = nmap.PortScanner()
    scanner.scan(ip_range, arguments='-p80')  # Change port number as per requirement
    hosts = scanner.all_hosts()
    for host in hosts:
        print(f"Host: {host}\tState: {scanner[host].state()}")
        write_file(f"Host: {host}\tState: {scanner[host].state()}\n")
    print(f"Scan complete. {len(hosts)} hosts found.")
    write_file(f"Scan complete. {len(hosts)} hosts found.\n")


# Part 02

def scan_port(target_ip, port_range):
    create_file()
    print(
        f"Port range scan from  range {port_range}  in ip address = {target_ip}  report:")
    write_file(
        f"\nPort range scan from range {port_range}  in ip address = {target_ip}  report:\n")
    # Create a new nmap scanner
    scanner = nmap.PortScanner()

    # Scan the specified target for open ports
    scanner.scan(target_ip, port_range)

    # Iterate over each protocol (e.g. TCP, UDP) in each host's scan results
    for protocol in scanner[target_ip].all_protocols():
        print(f"Protocol: {protocol}")
        write_file(f"Protocol: {protocol}\n")

        # Iterate over each port in each protocol's scan results
        ports = scanner[target_ip][protocol].keys()
        for port in ports:
            print(f"Port: {port}\tState: {scanner[target_ip][protocol][port]['state']}")
            write_file(f"Port: {port}\tState: {scanner[target_ip][protocol][port]['state']}\n")


# Part 03
def scan_service(target_ip, protocol, port_range):
    create_file()
    print(f"Services for ip address = {target_ip} with protocol = {protocol} and  port range = {port_range} report:")
    write_file(
        f"\nServices for ip address = {target_ip} with protocol = {protocol} and  port range = {port_range} report:\n")
    # Initialize the nmap module
    nm = nmap.PortScanner()

    # Use the nmap scan function to scan the target network for open port
    if protocol == "tcp":
        nm.scan(target_ip, arguments='-sS -p ' + port_range)
    else:
        nm.scan(target_ip, arguments='-sV -p ' + port_range)

    # Loop through each port in the open port list for the current host
    for port in nm[target_ip][protocol]:
        state = nm[target_ip][protocol][port]['state']
        service = nm[target_ip][protocol][port]['name']
        if state == "open":
            print('Port : %s/%s %s' % (port, nm[target_ip][protocol][port]['name'], state))
            write_file('Port : %s/%s %s\n' % (port, nm[target_ip][protocol][port]['name'], state))


# Part 04

def write_file(message):
    f = open(r"C:\Part02-Report.txt", "a")
    f.write(message)
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(title="subcommand")

    parser_scan_ip = subparsers.add_parser('scan_ip')
    parser_scan_ip.add_argument("-ip_range")
    parser_scan_ip.set_defaults(func=scan_ip)

    parser_get_open_port = subparsers.add_parser('scan_port')
    parser_get_open_port.add_argument("-target_ip")
    parser_get_open_port.add_argument("-port_range")
    parser_get_open_port.set_defaults(func=scan_port)

    parser_get_running_services = subparsers.add_parser('scan_service')
    parser_get_running_services.add_argument("-target_ip")
    parser_get_running_services.add_argument("-protocol")
    parser_get_running_services.add_argument("-port_range")
    parser_get_running_services.set_defaults(func=scan_service)

    args = parser.parse_args()

    arg_spec = inspect.getargspec(args.func)
    if arg_spec.keywords:
        # convert args to a dictionary
        args_for_func = vars(args)
    else:
        # get a subset of the dictionary containing just the arguments of func
        args_for_func = {k: getattr(args, k) for k in arg_spec.args}

    args.func(**args_for_func)
