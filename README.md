# kis2kml

A python script to parse wireless networks into a sqlite3 database
'wireless.db' and query this database to generate Google Earth KML files.

The script takes input from the wardriving suite Kismet, saved in netxml format,
and produces a kml file that allows easy visualization of the network data
inside Google Earth.

kis2kml is essentially a rewrite in Python of some of the functionality of
giskismet, which is written in Perl and comes bundled in with Kali Linux.

I don't mind giskismet, it does the job relatively well, but I wanted to be
able to make use of signal strength information in SQL queries, which giskismet
ignores, to be able to filter networks that one can realistically attach to. I
found Perl too hard to learn, so I taught myself Python and wrote a script to
do the job.

When exporting databased networks, you can export the whole database to a kml
file, or pass the program an optional SQL query to select networks that conform
with the given query. The SQL query must be inside double quotation marks.

I cannot comment on the legality or illegality of wardriving in your country
or area. Please keep this in mind before using this program to parse wardriving
data.

```
USAGE:

kis2kml [options]

   Options:
      -i <file-to-import.netxml>        Imports Kismet network data from a
                                        netxml file into a sqlite3 database
                                        ('wireless.db')
      -x <file-to-write-kml-to.kml>     Exports all network data to a Google
                                        Earth KML file.
           -q <'SQL query'>             Optional SQL query to restrict results
                                        to networks matching this query. Query
                                        has to be a valid SQL query and inside
                                        quote marks ('SQL query').
```                                   

### Usage examples:

```
kis2kml -i kismet-output-file.netxml

kis2kml -x all-database-contents.kml

kis2kml -x wep-only.kml -q "SELECT * FROM networks WHERE encryption = 'WEP'"

kis2kml -x strong_nets.kml \
        -q "SELECT * FROM networks WHERE max_signal_dbm > -60"

kis2kml -x strong_wep.kml \
        -q "SELECT * FROM networks WHERE max_signal_dbm > -60 AND \
        encryption = 'WEP'"

kis2kml -x open_but_cloaked.kml \
        -q "SELECT * FROM networks WHERE cloaked = 'true' AND \
        encryption = 'OPEN'"
```

### Tables in database ('wireless.db')

- networks
- run

### Table columns in networks:

-  'wn_num bssid' <br>
-  'essid' <br>
-  'encryption' <br>
-  'ssid_wpa_version' <br>
-  'ssid_type packets' <br>
-  'beaconrate' <br>
-  'wps' <br>
-  'wps_manuf' <br>
-  'dev_name' <br>
-  'model_name'<br>
-  'model_num' <br>
-  'cloaked' <br>
-  'manuf' <br>
-  'channel' <br>
-  'numclients' <br>
-  'first_seen' <br>
-  'last_seen' <br>
-  'max_speed' <br>
-  'maxseenrate' <br>
-  'max_signal_dbm'<br>
-  'max_noise_dbm' <br>
-  'peak_lat peak_lon'<br>

### Table columns in run:

- 'start_time'
