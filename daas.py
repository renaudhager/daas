#! /usr/bin/python
# -*- coding:utf-8 -*-

from flask import Flask
from flask import request
import pypureomapi
import ConfigParser
import json
import consul
import hashlib

daas = Flask(__name__)
conf_file = '/etc/daas.conf'

###################
# Utily functions #
###################


def validate_token(token, fqdn):
    """
    Function to authenticate request.
    @fqdn: fqdn associate to the token
    @token: token that needs to be validate.
    """

    conf = load_conf(conf_file)
    consul = consul_client(conf)

    key = conf['consul']['prefix'] + 'registered/' + fqdn + '/token'

    try:
        index, consul_data = consul.kv.get(key)
    except Exception as e:
        print "Error conenction to consul : %s" % e
        return False

    if consul_data is not None:
        consul_token = consul_data['Value']

        if consul_token == token:
            return True
        else:
            return False
    else:
        print "Key not found."
        return False


def create_lease(ip, mac, fqdn):
    """
    Function to create leases of a specificied MAC and IP.
    @fqdn: fqdn to set in the lease.
    @ip: ip to set in the lease.
    @mac: mac to set in the lease.
    """

    domain = get_domain(fqdn)
    conf = load_conf(conf_file)

    if domain in conf['dhcp_server']:
        dhcp_server = conf['dhcp_server'][domain]
        try:
            oma = pypureomapi.Omapi(hostname=dhcp_server, port=int(conf['omapi']['port']), username=conf['omapi']['keyname'], key=conf['omapi']['secret'], timeout=float(conf['omapi']['timeout']))
            oma.add_host_supersede_name(ip, mac, fqdn)
            return 201
        except pypureomapi.OmapiError, err:
            print "Creation failed, OMAPI error: %s" % (err,)
            return 500
    else:
        return 404


def lookup_lease(fqdn):
    """
    Function to lookup leases of a specificied fqdn.
    Use response.dump() to dump response message.
    @fqdn: fqdn to lookup.
    """

    domain = get_domain(fqdn)
    conf = load_conf(conf_file)

    if domain in conf['dhcp_server']:
        dhcp_server = conf['dhcp_server'][domain]
        try:
            oma = pypureomapi.Omapi(hostname=dhcp_server, port=int(conf['omapi']['port']), username=conf['omapi']['keyname'], key=conf['omapi']['secret'], timeout=float(conf['omapi']['timeout']))
            msg = pypureomapi.OmapiMessage.open(b"host")
            msg.obj.append((b"name", fqdn.encode('utf-8')))
            response = oma.query_server(msg)

            if response.opcode != pypureomapi.OMAPI_OP_UPDATE:
                raise pypureomapi.OmapiErrorNotFound()
                print "No lease found for %s" % fqdn
                return None
            try:
                return pypureomapi.unpack_mac(dict(response.obj)[b"hardware-address"])
            except KeyError:
                raise pypureomapi.OmapiErrorNotFound()

        except pypureomapi.OmapiErrorNotFound:
            print "No lease found for %s" % fqdn
            return None
        except pypureomapi.OmapiError, err:
            print "Retrieved lease failed, OMAPI error: %s" % (err,)
            return None
    else:
        return None


def delete_lease(mac, fqdn):
    """
    Function to delete leases of a specificied MAC @.
    @fqdn: fqdn use to find which dhcp server need to be reached.
    @mac: need to find lease associate to this mac.
    """

    domain = get_domain(fqdn)
    conf = load_conf(conf_file)

    if domain in conf['dhcp_server']:
        dhcp_server = conf['dhcp_server'][domain]
        try:
            oma = pypureomapi.Omapi(hostname=dhcp_server, port=int(conf['omapi']['port']), username=conf['omapi']['keyname'], key=conf['omapi']['secret'], timeout=float(conf['omapi']['timeout']))
            oma.del_host(mac)
            return 200
        except pypureomapi.OmapiError, err:
            print "Deletion failed, OMAPI error: %s" % (err,)
            return 500
    else:
        return 404


def load_conf(conf_file):
    """
    Function to load config file and return a dict.
    Config need be a ini config file.
    @conf_file: path to configuration file.
    """

    conf_tmp = {}
    config = ConfigParser.ConfigParser()
    config.read(conf_file)
    sections = config.sections()

    i = 0
    for section in sections:
        # Parsing options for each section
        conf_tmp.update({section: {}})
        options = config.options(sections[i])
        for option in options:
            conf_tmp[section][option] = config.get(section, option)

        i += 1

    if len(conf_tmp) > 0:
        return conf_tmp
    else:
        return None


def get_domain(fqdn):
    """
    Function to extract domain fron fqdn.
    @fqdn: fqdn.
    Example :
        foo.bar => bar
        foo.bar.fif => bar.fif
    """

    domain = fqdn.split('.', 1)
    return domain[1]


def consul_client(conf):
    """
    """

    return consul.Consul(host=conf['consul']['host'], port=conf['consul']['port'], scheme=conf['consul']['scheme'])


#####################
# Route definitions #
#####################


@daas.route('/')
def index():
    """
    Default API route.
    """
    return "Nothing to see here. ", 404


@daas.route('/configuration', methods=['GET'])
def configuration():
    """
    Print conf
    """
    conf = load_conf(conf_file)
    return json.dumps(conf)


@daas.route('/register', methods=['POST'])
def register():
    """
    API route to register a box into KV.
    @fqdn: fqdn to register.
    """

    conf = load_conf(conf_file)
    consul = consul_client(conf)

    fqdn = request.args.get('fqdn')
    token = hashlib.sha256(fqdn).hexdigest()
    key = conf['consul']['prefix'] + 'registered/' + fqdn + '/token'

    try:
        consul.kv.put(key, token)
        return token, 201
    except Exception as e:
        print e
        return "Error while creating the key in Consul", 500


@daas.route('/unregister', methods=['POST'])
def unregister():
    """
    API route to register a box into KV.
    @fqdn: fqdn to register.
    @token: token used to validate host identity.
    """

    fqdn = request.args.get('fqdn')
    token = request.args.get('token')

    conf = load_conf(conf_file)
    consul = consul_client(conf)

    key = conf['consul']['prefix'] + 'registered/' + fqdn + '/token'

    if validate_token(token, fqdn):
        try:
            consul.kv.delete(key)
            return fqdn + " has been unregistered.", 200
        except Exception as e:
            print e
            return "Error while deleting the key in Consul", 500
    else:
        return "Unauthorized", 401


@daas.route('/lookup', methods=['GET'])
def lookup():
    """
    API route to get mac for specificied fqdn.
    @fqdn: fqdn to lookup.
    """

    fqdn = request.args.get('fqdn')

    mac = lookup_lease(fqdn)
    if mac is not None:
        return "Lease existing for " + fqdn + " with mac " + mac + "."
    else:
        return "Lease not found.", 404


@daas.route('/create', methods=['POST'])
def create():
    """
    API route to create DHCP leases.
    @fqdn: fqdn to set in the lease.
    @ip: ip to set in the lease.
    @mac: mac to set in the lease.
    @token: token used to validate host identity.
    """

    fqdn = request.args.get('fqdn')
    ip = request.args.get('ip')
    mac = request.args.get('mac')
    token = request.args.get('token')

    if validate_token(token, fqdn):
        # Checking that there is no existing lease
        mac2 = lookup_lease(fqdn)
        if mac2 is None:
            return_code = create_lease(ip, mac, fqdn)
            if return_code == 201:
                return "Lease created for " + ip + " and mac " + mac + ".", 201
            else:
                return "Error during leases creation.", return_code
        else:
            return "Lease already exist for " + fqdn + " associate to mac " + mac + ".", 200
    else:
        return "Unauthorized", 401


@daas.route('/delete', methods=['POST'])
def delete():
    """
    API route to delete DHCP leases.
    @fqdn: fqdn use to find lease that need to be deleted.
    @token: token used to authenticate the request.
    """

    fqdn = request.args.get('fqdn')
    token = request.args.get('token')

    mac = lookup_lease(fqdn)
    if validate_token(token, fqdn):
        if mac is not None:
            return_code = delete_lease(mac, fqdn)
            if return_code == 200:
                return "deleting lease for mac " + mac + ".", 200
            else:
                return "Error during leases creation.", return_code
        else:
            return "Lease not found", 404
    else:
        return "Unauthorized", 401


if __name__ == '__main__':

    daas.run(debug=True)

    # # Loading conf
    # conf = load_conf(conf_file)
    # if conf is not None:
    #     print "Configuration from %s has been correctly loaded." % conf_file
    #
    #     # Creating consul object
    #     consul_client = consul.Consul(host=conf['consul']['host'], port=conf['consul']['port'], scheme=conf['consul']['scheme'])
    #     # Starting app
    #     daas.run(debug=True)
    #     # daas.run()
    #
    # else:
    #     print "Error during configuration loading. Check your config file : %s" % conf_file
