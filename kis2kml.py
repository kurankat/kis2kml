#! /usr/bin/env python
# kis2kml.py is a script to process Kismet netxml files
# into Google Earth KML for visualization.

import xml.etree.ElementTree as xml
import sqlite3 as sql
import sys, getopt
from os.path import exists

total_discovered = 0
total_saved = 0
total_exported = 0

def usage():
    print """Usage: kisiter.py [options]
        Options: can be either import (-i) or export (-x).
        \t\t-i <XML input file>
        \t\t-x <KML export file>  # Export file can have optional -q SQL query
        \t\t-q \'<SQL query\'>'
        """

### SECTION 1: Loading networks from Kismet netxml

# Open xml file and load it into a etree.ElementTree object
# Create a list of tree nodes that contain infrastructure networks
# Parse xml into a list of dictionaries with all important network data
def load_nets_from_xml(xfile):
    global total_discovered
    netnodes = []
    netlist_dicts = []

    print "Reading network information from %s" %xfile

    # Open Kismet .netxml file and load into list of nodes
    with open(xfile, 'rt') as kismet:
            tree = xml.parse(kismet)
    netnodes = pop_xml_netlist(tree)

    # For each wireless network node, create a dictionary, and append it to
    # a list of network dictionaries
    for node in netnodes:
        netlist_dicts.append(populate_net_dict(node))
    total_discovered = len(netnodes)

    return netlist_dicts

# Function to return a list of eTree nodes. Takes the whole XML tree as the
# argument and returns a list[] of nodes containing only infrastructire networks
def pop_xml_netlist(whole_tree):
    nodelist = []
    for node in whole_tree.findall('.//wireless-network'):
        if (node.attrib.get('type') == 'infrastructure'):
            nodelist.append(node)
    return nodelist

# Populate values of network dictionary from xml node
def populate_net_dict(wireless_node):
    wn = make_net_dict()
    wn['wn_num'] = wireless_node.attrib['number']
    wn['first_seen'] = wireless_node.attrib['first-time']
    wn['last_seen'] = wireless_node.attrib['last-time']
    wn['placeholder_encryption'] = []
    wn['clients'] = []

    # Iterate through first-level nodes and fill values into empty dictionary
    for lev1 in wireless_node:

        # Append the MAC address of clients as a list
        if lev1.tag == 'wireless-client':
            for cinfo in lev1:
                for ctag in cinfo.iter('client-mac'):
                    wn['clients'].append(ctag.text)

        # Loop through second-level nodes in SSID
        if lev1.tag == 'SSID':
            for ssid_info in lev1:
                # assign multiple ecryption fields to a temporary list
                for e in ssid_info.iter('encryption'):
                    wn['placeholder_encryption'].append(e.text)

                if ssid_info.tag == 'type':
                    wn['ssid_type'] = ssid_info.text
                if ssid_info.tag == 'max-rate':
                    wn['max_speed'] = ssid_info.text
                if ssid_info.tag == 'packets':
                    wn['packets'] = ssid_info.text
                if ssid_info.tag == 'beaconrate':
                    wn['beaconrate'] = ssid_info.text
                if ssid_info.tag == 'wps':
                    wn['wps'] = ssid_info.text
                if ssid_info.tag == 'wps-manuf':
                    wn['wps_manuf'] = ssid_info.text
                if ssid_info.tag == 'dev-name':
                    wn['dev_name'] = ssid_info.text
                if ssid_info.tag == 'model-name':
                    wn['model_name'] = ssid_info.text
                if ssid_info.tag == 'model-num':
                    wn['model_num'] = ssid_info.text
                if ssid_info.tag == 'wpa-version':
                    wn['ssid_wpa_version'] = ssid_info.text
                if ssid_info.tag == 'essid':
                    if ssid_info.attrib['cloaked'] == 'true':
                        wn['essid'] = ""
                    else: # Replace some characters that cause problems in KML
                        tempessid = ssid_info.text
                        wn['essid'] = tempessid.replace('&', '').replace('<', '').replace('>', '')
                    wn['cloaked'] = ssid_info.attrib['cloaked']

        if lev1.tag == 'BSSID':
            wn['bssid'] = lev1.text
        if lev1.tag == 'manuf':
            wn['manuf'] = lev1.text
        if lev1.tag == 'channel':
            wn['channel'] = lev1.text
        if lev1.tag == 'maxseenrate':
            wn['maxseenrate'] = lev1.text

        # Loop through snr information
        if lev1.tag == 'snr-info':
            for snr_info in lev1:
                if snr_info.tag == 'max_signal_dbm':
                    wn['max_signal_dbm'] = snr_info.text
                if snr_info.tag == 'max_noise_dbm':
                    wn['max_noise_dbm'] = snr_info.text

        # Loop through GPS information
        if lev1.tag == 'gps-info':
            for gps_info in lev1:
                if gps_info.tag == 'peak-lat':
                    wn['peak_lat'] = gps_info.text
                if gps_info.tag == 'peak-lon':
                    wn['peak_lon'] = gps_info.text
    # select appropriate text for encryption field
    wn['encryption'] = populate_encryption(wn['placeholder_encryption'])
    wn['numclients'] = len(wn['clients'])

    print "Found infrastructure network with BSSID: %s - encryption: %s" \
             % (wn['bssid'], wn['encryption'])
    return wn

# Create an empty network dictionary with all needed keys
def make_net_dict():
    keys = ['wn_num',
            'first_seen',
            'last_seen',
            'ssid_type',
            'max_speed',
            'packets',
            'beaconrate',
            'wps',
            'wps_manuf',
            'dev_name',
            'model_name',
            'model_num',
            'placeholder_encryption',
            'encryption',
            'ssid_wpa_version',
            'cloaked',
            'essid',
            'bssid',
            'manuf',
            'channel',
            'maxseenrate',
            'max_signal_dbm',
            'max_noise_dbm',
            'clients',
            'numclients',
            'peak_lat',
            'peak_lon']
    network = {key: None for key in keys}
    return network

# based in the entries in placeholder_encryption, return correct text
def populate_encryption(placeholder_list):
    encryption = 'UNKNOWN'

    if 'WEP' in placeholder_list and 'WPA' in placeholder_list:
        encryption = 'WEP + WPA'
    elif 'WEP' in placeholder_list:
        encryption = 'WEP'
    elif 'WPA+TKIP' in placeholder_list and 'WPA+PSK' in placeholder_list:
        encryption = 'WPA+TKIP/PSK'
    elif 'WPA+TKIP' in placeholder_list:
        encryption = 'WPA+TKIP'
    elif 'WPA+PSK' in placeholder_list:
        encryption = 'WPA+PSK'
    elif 'WPA+AES-CCM' in placeholder_list:
        encryption = 'WPA-MGT'
    else:
        encryption = 'OPEN'

    return encryption


### SECTION 2: Saving networks to a sqlite3 database

# Open connection to database and loop through networks,
# adding appropriate ones to the database. Mostly self-explanatory
def save_nets_to_db(netlist, dfile):
    global total_saved
    con = sql.connect(dfile)
    create_net_table(con)
    with con:
        for net in netlist:
            add_net_to_db(net, con)


# If networks table does not exist, create empty table in database
def create_net_table(con):
    with con:
        cur = con.cursor()
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS networks(
                        wn_num INT,
                        bssid TEXT,
                        essid TEXT,
                        encryption TEXT,
                        ssid_wpa_version TEXT,
                        ssid_type TEXT,
                        packets INT,
                        beaconrate INT,
                        wps TEXT,
                        wps_manuf TEXT,
                        dev_name TEXT,
                        model_name TEXT,
                        model_num TEXT,
                        cloaked TEXT,
                        manuf TEXT,
                        channel INT,
                        numclients INT,
                        first_seen TEXT,
                        last_seen TEXT,
                        max_speed INT,
                        maxseenrate INT,
                        max_signal_dbm INT,
                        max_noise_dbm INT,
                        peak_lat TEXT,
                        peak_lon TEXT)
                   """)

# Check if network exists in database.
# If it doesn't exist save it.
# If it exists, and stored network is weaker, erase it and save new data.
def add_net_to_db(netdict, con):
    global total_saved
    exists, morepower = check_if_net_exists(netdict, con)
    if not exists or morepower:
        if exists and morepower:
            delete_net_from_db(netdict, con)
        netlist = make_ordered_netlist(netdict)
        print "Adding wireless network with BSSID: %s to database" \
                %netdict['bssid']

        cur = con.cursor()
        cur.execute("""
                    INSERT INTO networks VALUES(?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )""", netlist)
        total_saved += 1

def if_net_new(netdict, con):
    pass

def if_net_weaker(netdict, con):
    pass

def if_net_stronger(netdict, con):
    pass

# Check if MAC address of network already in DB
def check_if_net_exists(netdict, con):
    newmac = netdict['bssid']
    maxsig = int(netdict['max_signal_dbm'])
    db_strength = None
    is_more_powerful = False
    exists = False

    # iterate through bssids in database to see if it's already in
    cur = con.cursor()
    cur.execute("SELECT bssid FROM networks")
    for row in cur:
        if newmac in row:
            exists = True

    # compare max_signal_dbm of two networks
    if exists:
        with con:
            cur = con.cursor()
            cur.execute('''SELECT max_signal_dbm FROM networks WHERE bssid = ?''', \
                            (newmac,))
            db_strength = int(cur.fetchone()[0])

    if maxsig > db_strength:
        is_more_powerful = True

    return exists, is_more_powerful

# Turn each net dictionary into a list, return list
def make_ordered_netlist(netdict):
    netl = (
            int(netdict['wn_num']),
            netdict['bssid'],
            netdict['essid'],
            netdict['encryption'],
            netdict['ssid_wpa_version'],
            netdict['ssid_type'],
            netdict['packets'],
            netdict['beaconrate'],
            netdict['wps'],
            netdict['wps_manuf'],
            netdict['dev_name'],
            netdict['model_name'],
            netdict['model_num'],
            netdict['cloaked'],
            netdict['manuf'],
            int(netdict['channel']),
            int(netdict['numclients']),
            netdict['first_seen'],
            netdict['last_seen'],
            netdict['max_speed'],
            int(netdict['maxseenrate']),
            int(netdict['max_signal_dbm']),
            int(netdict['max_noise_dbm']),
            netdict['peak_lat'],
            netdict['peak_lon']
        )
    return netl

# Erase existing weaker networks from db
def delete_net_from_db(netdict, con):
    cur = con.cursor()
    cur.execute('''DELETE from networks WHERE bssid = ?''', \
                    (netdict['bssid'],))


### SECTION 3: Loading networks from database to create KML

# Load every network in the database.
def load_all_nets_from_db(dfile):
    netlist = []
    con = sql.connect(dfile)
    with con:
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * from networks")
        rows = cur.fetchall()
        for row in rows:
            rowdic = parse_db_row(row)
            netlist.append(rowdic)
    return netlist

# Load networks that match a specific SQL query
def load_from_db_with_sql_arg(dfile, sql_arg):
    query = sql_arg
    netlist = []
    con = sql.connect(dfile)
    with con:
        con.row_factory = sql.Row
        cur = con.cursor()
        try: # In case SQL can't be understood
            cur.execute(query)
            rows = cur.fetchall()

        except sql.OperationalError as err:
            print "Error: Your SQL query could not be interpreted"
            print "--->\t %s\n" % query
            print "Python says:  \'%s\'\n" % str(err)
            usage()
            sys.exit(2)

        for row in rows:
            rowdic = parse_db_row(row)
            netlist.append(rowdic)

    return netlist

# Parse rows of database into dictionary
def parse_db_row(row):
    wndb = make_net_dict()
    for item in row.keys():
        wndb[item] = row[item]
    return wndb

### SECTION 4: Crafting KML
# Assemble all the KML pieces into a list with one line per list item
def make_kml(netlist):
    kmllist = []
    kmllist = create_kml_headers(kmllist)
    kmllist = append_kml_styles(kmllist, netlist)
    kmllist = append_kml_placemarks(kmllist, netlist)
    kmllist = close_kml(kmllist)
    return kmllist

# Create header rows
def create_kml_headers(kmllist):
    kmllist.append('<?xml version="1.0" encoding="UTF-8"?>')
    kmllist.append('<kml xmlns="http://www.opengis.net/kml/2.2">')
    kmllist.append('\t<Document>')
    kmllist.append('\t\t<name>Wireless Networks</name>')
    kmllist.append('\t\t<description>Wireless networks parsed from Kismet xml</description>')
    return kmllist

# For every encryption type found in query, create a style
def append_kml_styles(kmllist, netlist):
    netcolours = {'WEP':'0090FF', 'WPA':'0000FF', 'OPEN':'00FF00'}
    encryptions = []
    for n in netlist:
        if 'WEP' in n['encryption'] and 'WEP' not in encryptions:
            encryptions.append('WEP')
        if 'WPA' in n['encryption'] and 'WPA' not in encryptions:
            encryptions.append('WPA')
        if 'OPEN' in n['encryption'] and 'OPEN' not in encryptions:
            encryptions.append('OPEN')

    for e in encryptions:
        kmllist.append('\t\t<Style id="%s broadcasting">' % e)
        kmllist.append('\t\t\t<IconStyle>')
        kmllist.append('\t\t\t\t<color>ff%s</color>' % netcolours[e])
        kmllist.append('\t\t\t\t<scale>1</scale>')
        kmllist.append('\t\t\t\t<Icon>')
        kmllist.append('\t\t\t\t\t<href>http://maps.google.com/mapfiles/kml/shapes/target.png</href>')
        kmllist.append('\t\t\t\t</Icon>')
        kmllist.append('\t\t\t</IconStyle>')
        kmllist.append('\t\t</Style>')
        kmllist.append('\t\t<Style id="%s cloaked">' % e)
        kmllist.append('\t\t\t<IconStyle>')
        kmllist.append('\t\t\t\t<color>7f%s</color>' % netcolours[e])
        kmllist.append('\t\t\t\t<scale>1</scale>')
        kmllist.append('\t\t\t\t<Icon>')
        kmllist.append('\t\t\t\t\t<href>http://maps.google.com/mapfiles/kml/shapes/target.png</href>')
        kmllist.append('\t\t\t\t</Icon>')
        kmllist.append('\t\t\t</IconStyle>')
        kmllist.append('\t\t</Style>')

    return kmllist

# Create KML Placemark text and append to list for every network in query
def append_kml_placemarks(kmllist, netlist):
    global total_exported
    nets = netlist
    kmllist.append('\t\t<Folder>')
    kmllist.append('\t\t\t<name>Placemarks</name>')
    kmllist.append('\t\t\t<description>Wireless network locations</description>')
    for net in netlist:
        kmllist.append('\t\t\t<Placemark>')
        if net['essid']:
            kmllist.append('\t\t\t\t<name>%s</name>' % net['essid'])
        else:
            kmllist.append('\t\t\t\t<name></name>')
        if 'WEP' in net['encryption']:
            if net['cloaked'] == 'true':
                kmllist.append('\t\t\t\t<styleUrl>#WEP cloaked</styleUrl>')
            else:
                kmllist.append('\t\t\t\t<styleUrl>#WEP broadcasting</styleUrl>')

        if 'WPA' in net['encryption']:
            if net['cloaked'] == 'true':
                kmllist.append('\t\t\t\t<styleUrl>#WPA cloaked</styleUrl>')
            else:
                kmllist.append('\t\t\t\t<styleUrl>#WPA broadcasting</styleUrl>')

        if 'OPEN' in net['encryption']:
            if net['cloaked'] == 'true':
                kmllist.append('\t\t\t\t<styleUrl>#OPEN cloaked</styleUrl>')
            else:
                kmllist.append('\t\t\t\t<styleUrl>#OPEN broadcasting</styleUrl>')
        kmllist.append('\t\t\t\t<description><![CDATA[BSSID:%s<br>%s<br>Encryption: %s<br>Channel: %d<br>Signal: %d<br>Current Clients: %d<br>]]></description>' \
                        % (net['bssid'],net['last_seen'], net['encryption'], \
                        net['channel'], net['max_signal_dbm'], net['numclients']))
        kmllist.append('\t\t\t\t<Point>')
        kmllist.append('\t\t\t\t\t<coordinates>%s,%s,0</coordinates>' % (net['peak_lon'], net['peak_lat']))
        kmllist.append('\t\t\t\t</Point>')
        kmllist.append('\t\t\t</Placemark>')
        print "Found network with BSSID: %s ** Exporting to KML file" % net['bssid']
        total_exported += 1

    kmllist.append('\t\t</Folder>')
    return kmllist

# Add the closing lines
def close_kml(kmllist):
    kmllist.append('\t</Document>')
    kmllist.append('</kml>')
    return kmllist

# Save KML list to file one row at a time
def kml_to_file(kml, filename):
    writeable = check_write(filename)
    if writeable: # This is probably obsolete since program exits if user responds 'n'
        with open(filename, "w") as f:
            for line in kml:
                f.write("%s\n" % line)

# Check if KML file already exists. If so, ask if OK to overwrite.
def check_write(filename):
    if exists(filename):
        print "\nFile %s already exists at this location." % filename
        action = raw_input("Overwrite? (y/N)\t")
        if action in ('Y','y','Yes','yes'):
            return True
        elif action in ('N','n','No','no'):
            print "Ok (quitting)"
            sys.exit(2)
    else:
        return True

### SECTION 5: Main
def main(argv):
    xmlsource = ''
    database = 'wireless.db'
    query = ''

    print "Welcome to the Kismet netxml file parser\n"

    try:
        opts, args = getopt.getopt(argv,"hi:x:q:")

    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)

    if len(argv) == 0:
        usage()
        sys.exit()

    for opt, arg in opts:
        if opt == "-q":
            query = arg

    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()

        elif opt == "-i":
            inputfile = arg
            netlist = load_nets_from_xml(inputfile)
            save_nets_to_db(netlist, database)
            print "\nFound %d wireless networks in Kismet netxml file" \
                    % total_discovered
            print "Added %d wireless networks to SQL database" % total_saved

        elif opt == "-x":
            exportfile = arg
            if len(query) > 0:
                db_list = load_from_db_with_sql_arg(database, query)
            else:
                db_list = load_all_nets_from_db(database)
            kml_content = make_kml(db_list)
            kml_to_file(kml_content, exportfile)
            print "\nExported %d networks to KML file" % total_exported

        elif opt == "-q":
            pass

if __name__ == "__main__":
    main(sys.argv[1:])


# Debugging functions
def print_node(infranode):
    print "\n\n"
    for n in infranode.iter():
        print n.tag, n.text, n.attrib

def print_field(netlist, field):
    print "\n\n"
    for net in netlist:
        for i in net:
            if i == str(field):
                print i, net[i]

def print_dict(dicty):
    print "\n\n"
    for i in dicty:
        print i, dicty[i]

def print_list(netl):
    for ls in netl:
        print ls
    print "\n"
