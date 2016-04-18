#!/usr/bin/env python

import urllib2, csv, subprocess, random, getopt, sys, os, uuid, shutil

__url__ = 'https://raw.githubusercontent.com/jedisct1/dnscrypt-proxy/master/dnscrypt-resolvers.csv'
__sig_url__ = 'https://raw.githubusercontent.com/jedisct1/dnscrypt-proxy/master/dnscrypt-resolvers.csv.minisig'
__file_name__ = '/etc/dnscrypt-proxy/' + __url__.split('/')[-1]
__tmp_file__ = '/tmp/' + str(uuid.uuid4())
__sig_file_name__ = '/etc/dnscrypt-proxy/' + __sig_url__.split('/')[-1]
__tmp_sig_file_name__ = __tmp_file__ + '.minisig'
__daemon__ = os.getenv('DAEMON', '/usr/local/sbin/dnscrypt-proxy')
__sig__ = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'

def curl_file(url, file_name):
    u = urllib2.urlopen(url)
    f = open(file_name, 'wb')
    meta = u.info()

    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        f.write(buffer)
    f.close()

def get_resolver_list(file_name):
    servers = []
    with open(file_name, 'r') as csvfile:
        input_file = csv.DictReader(open(file_name))
        servers = [r for r in input_file]
    return servers

def get_good_resolvers(servers):
    safe_dns = []
    #safe_dns = [s for s in servers if '443' == s.get('Resolver address').split(':')[-1]]
    for s in servers:
        if '443' == s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)
        if '53' == s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)
        if '5353' == s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)
        if '1053' == s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)
        if '2053' == s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)
        if '27015' == s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)
        if '.' in s.get('Resolver address').split(':')[-1]:
            safe_dns.append(s)

    safe_dns = [s for s in safe_dns if 'yes' in s.get('No logs')]

    safe_dns = [s for s in safe_dns if 'Australia' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'AU' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Viet Nam' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'South Africa' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Viet Nam' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Singapore' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Turkey' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Russia' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Hong Kong' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Anycast' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Ireland' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'New Zealand' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'Tanzania' not in s.get('Location')]
    safe_dns = [s for s in safe_dns if 'United Kingdom' not in s.get('Location')]

    return safe_dns

def get_dnssec_resolvers(servers):
    return [s for s in servers if 'yes' in s.get('DNSSEC validation')]

def start_dns(resolvers, ports):
    random.shuffle(resolvers)
    for p, r in zip(ports, resolvers):
        if '[' in r.get('Resolver address'):
            subprocess.Popen([__daemon__, '-d', '-u', 'dnscrypt-proxy', '-a', '[::1]:' + str(p), '-r', r.get('Resolver address'), '-N', r.get('Provider name'), '-k', r.get('Provider public key')])
        else:
            subprocess.Popen([__daemon__, '-d', '-u', 'dnscrypt-proxy', '-a', '127.0.0.1:' + str(p), '-r', r.get('Resolver address'), '-N', r.get('Provider name'), '-k', r.get('Provider public key')])

def verify_sig(file, sig):
    cmd = ['/usr/local/bin/minisign', '-VP', sig, '-m', file]
    try:
        proc = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        print 'ERROR: Invalid signature detected. Exiting.'
        return False

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hp:c:n", ["start-port=", "resolver-count=", "no-curl"])
    except getopt.GetoptError:
        print 'ERROR'
        sys.exit(2)

    start_port = '9031'
    resolver_count = '0'
    curl = True
    for opt, arg in opts:
        if opt == '-h':
            print sys.argv[0] + ' -p <starting port> -c <resolver count>'
            sys.exit()
        elif opt in ("-p", "--start-port"):
            start_port = arg
        elif opt in ("-c", "--resolver-count"):
            resolver_count = arg
        elif opt in ("-n", "--no-curl"):
            curl = False

    if curl:
        try:
            curl_file(__url__, __tmp_file__)
            curl_file(__sig_url__, __tmp_sig_file_name__)
        except:
            print 'ERROR curling resolver list. Using default list.'

        if verify_sig(__tmp_file__, __sig__):
            shutil.move(__tmp_file__, __file_name__)
            shutil.move(__tmp_sig_file_name__, __sig_file_name__)

    servers = get_resolver_list(__file_name__)
    safe_dns = get_good_resolvers(servers)

    dnssec_servers = get_dnssec_resolvers(safe_dns)

    if len(dnssec_servers) >= 10:
        safe_dns = dnssec_servers

    if resolver_count == '0':
        if len(safe_dns) <= 8:
            resolver_count = '2'
        elif len(safe_dns) <= 10:
            resolver_count = '3'
        else:
            resolver_count = '4'

    port_list = []
    for i in range(int(resolver_count)):
        port_list.append(i + int(start_port))

    start_dns(safe_dns, port_list)

if __name__ == "__main__":
    main(sys.argv[1:])

