
# NSC provisioning scripts for EMS

## Usage:

./run.sh [provision-options] -- [request-options]

provisioning-options:

  --dump         dump the configuration data and exit
  --no-update    do not attempt update if an update package is present
  --force-apply  apply and restart network even if no changes have been made
  --no-restart   do not restart the network after configuration
  --no-request   do not contact the server (via server-request script)

request-options:

  --ip          IP address of the SBC (same IP used for connecting to EMS)
  --server      Server socket where request should be sent
  --key         REST API key
  --current     A string which will be provided by us as an identifier to validate the API call
  --macid       MAC address of the primary ethernet port
  --name        An unique name for the SBC
  --description Description for the particular SBC
  --venue       Information on the location of the SBC
  --altmacid    MAC address of secondary ethernet port, if any
  --mediamacid  MAC Address of media interface
  --hdserial    Serial number of the hard disk
  --ca          PEM file for secure connection. If not present, uses HTTP request instead of HTTPS
  --config      Alternativelly, a config file (.ini) with command line parameters.
                Command line parameters override parameters on config file
