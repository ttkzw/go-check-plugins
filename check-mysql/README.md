# check-mysql

## Description

Checks for MySQL.

## Synopsis
```
check-mysql connection --host=127.0.0.1 --port=3306 --user=USER --password=PASSWORD --warning=250 --critical=280
```

## Installation

First, build this program.

```
go get github.com/mackerelio/go-check-plugins
cd $(go env GOPATH)/src/github.com/mackerelio/go-check-plugins/check-mysql
go install
```

Or you can use this program by installing the official Mackerel package. See [Using the official check plugin pack for check monitoring - Mackerel Docs](https://mackerel.io/docs/entry/howto/mackerel-check-plugins).


Next, you can execute this program :-)

```
check-mysql connection --host=127.0.0.1 --port=3306 --user=USER --password=PASSWORD --warning=250 --critical=280
check-mysql replication --host=127.0.0.1 --port=3306 --user=USER --password=PASSWORD --warning=5 --critical=10
```


## Setting for mackerel-agent

If there are no problems in the execution result, add a setting in mackerel-agent.conf .

```
[plugin.checks.check-mysql-sample]
command = ["check-mysql", "connection", "--host", "127.0.0.1", "--port", "3306", "--user", "USER", "--password", "PASSWORD", "--warning", "250", "--critical", "280"]
```

## Usage
### Subcommands

```
  uptime
  readonly
  replication
  connection
  group-replication
```

### Options
#### `uptime` subcommand

Checks the MySQL server uptime.

```
  -H, --host=     Hostname (default: localhost)
  -p, --port=     Port (default: 3306)
  -S, --socket=   Path to unix socket
  -u, --user=     Username (default: root)
  -P, --password= Password [$MYSQL_PASSWORD]
  -c, --critical= critical if the uptime less than (default: 0)
  -w, --warning=  warning if the uptime less than (default: 0)
```

#### `readonly` subcommand

Checks the MySQL server is readonly or not.

```
  -H, --host=     Hostname (default: localhost)
  -p, --port=     Port (default: 3306)
  -S, --socket=   Path to unix socket
  -u, --user=     Username (default: root)
  -P, --password= Password [$MYSQL_PASSWORD]
```

#### `replication` subcommand

Checks MySQL replication status and its second behind master.

```
  -H, --host=     Hostname (default: localhost)
  -p, --port=     Port (default: 3306)
  -S, --socket=   Path to unix socket
  -u, --user=     Username (default: root)
  -P, --password= Password [$MYSQL_PASSWORD]
  -c, --critical= critical if the seconds behind master is over (default: 250)
  -w, --warning=  warning if the seconds behind master is over (default: 200)
```

#### `connection` subcommand

Checks the number of MySQL connections.

```
  -H, --host=     Hostname (default: localhost)
  -p, --port=     Port (default: 3306)
  -S, --socket=   Path to unix socket
  -u, --user=     Username (default: root)
  -P, --password= Password [$MYSQL_PASSWORD]
  -c, --critical= critical if the number of connection is over (default: 250)
  -w, --warning=  warning if the number of connection is over (default: 200)
```

#### `group-replication` subcommand

Checks the status of MySQL Group Replication.

```
  -H, --host=           Hostname (default: localhost)
  -p, --port=           Port (default: 3306)
  -S, --socket=         Path to unix socket
  -u, --user=           Username (default: root)
  -P, --password=       Password [$MYSQL_PASSWORD]
      --local-hostname= Local hostname as a group member. See performance_schema.replication_group_members.
      --local-port=     Local port number as a group member. See performance_schema.replication_group_members. (default: 3306)
  -g, --group-members   Detect anomalies of other group members
```

## For more information

Please execute `check-mysql -h` and you can get command line options.
