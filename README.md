
# NSC provisioning scripts for EMS

## Getting started

This software performs initial network configuration and provisioning
on EMS servers.

Options required for provisioning and initial network setup should be
configured on the "config.toml" file, which contains documentation about
each supported option and defaults for most parameters.

The "request" phase also supports some commands passed via command line,
which override the values found in the configuration file (if specified).

Some options can be automatically inferred: a special format is supported
for a few parameters section "EMS", namely "ip", "macid", "altmacid" and
"mediamacid". For these parameters, passing a network device name between
parenthesis will automatically find the option from the interface, either
using the first static IP on the interface (for "ip") or the MAC address
or the interface (*macid options).

First step is to adjust "config.toml" as required:

  # <favourite-editor> config.toml

Provisioning is performed by calling the "run.sh" script, which runs all
the steps required for initial configuration and registration on the EMS
server.

Second step is to run the script - by default, calling it without any
arguments will perform all the required steps automatically:

  # ./run.sh

A few command line parameters are supported (shown below).


## Command line usage and options:

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
    --current     An identifier used to validate the API call
    --macid       MAC address of the primary ethernet port
    --name        An unique name for the SBC
    --description Description for the particular SBC
    --venue       Information on the location of the SBC
    --altmacid    MAC address of secondary ethernet port, if any
    --mediamacid  MAC Address of media interface
    --hdserial    Serial number of the hard disk
    --ca          PEM file for secure connection (HTTP is used if not present)
    --config      Alternativelly, a config file (.ini) with command line parameters.
                  Command line parameters override parameters on config file
