# kis2kml
A python script to parse Kismet netxml into a SQL database and query it to generate Google Earth KML files.

I don't mind Giskismet, it does the job relatively well, but I wanted to be able make use of signal strength information in SQL queries, which Giskismet ignores, to filter networks that one can realistically attach to. I found Perl too hard to learn, so I wrote a Python script to do the job.

USAGE:
kis2kml [options]

Options:
  -i <file-to-import.netxml>       Imports Kismet network data from a netxml file into a sqlite3 database ('wireless.db')
  -x <file-to-write-kml-to.kml>    Exports all network data to a Google Earth KML file.
        -q <'SQL query'>           Optional SQL query to restrict results to networks matching this query.
                                   Query has to be a valid SQL query and inside quote marks.
                                   
Table columns in database:

  wn_num bssid <br>
  essid encryption <br>
  ssid_wpa_version <br>
  ssid_type packets <br>
  beaconrate <br>
  wps <br>
  wps_manuf <br>
  dev_name <br>
  model_name<br>
  model_num <br>
  cloaked <br>
  manuf <br>
  channel <br>
  numclients <br>
  first_seen <br>
  last_seen <br>
  max_speed <br>
  maxseenrate <br>
  max_signal_dbm<br>
  max_noise_dbm <br>
  peak_lat peak_lon<br>
