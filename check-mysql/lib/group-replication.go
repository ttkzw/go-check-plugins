package checkmysql

import (
	"fmt"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
	"github.com/ziutek/mymysql/mysql"
)

type groupReplicationOpts struct {
	mysqlSetting
	LocalHostname string `long:"local-hostname" description:"Local hostname as a group member. See performance_schema.replication_group_members."`
	LocalPort     string `long:"local-port" default:"3306" description:"Local port number as a group member. See performance_schema.replication_group_members."`
	GroupMember   bool   `short:"g" long:"group-members" description:"Detect anomalies of other group members"`
}

type groupMember struct {
	Host  string
	State string
}

const (
	stateOnline      = "ONLINE"
	stateRecovering  = "RECOVERING"
	stateOffline     = "OFFLINE"
	stateError       = "ERROR"
	stateUnreachable = "UNREACHABLE"
)

// getLocalMemberState returns the state of the local host.
func getLocalMemberState(db *mysql.Conn, localHostname string, localPort string) (string, error) {
	stmt, err := (*db).Prepare(`
SELECT MEMBER_STATE 
FROM   performance_schema.replication_group_members 
WHERE  MEMBER_HOST = ? AND MEMBER_PORT = ?;
`)
	if err != nil {
		return "", fmt.Errorf("couldn't execute query")
	}

	rows, res, err := stmt.Exec(localHostname, localPort)
	if err != nil {
		return "", fmt.Errorf("couldn't execute query")
	}

	if len(rows) == 0 {
		return "", fmt.Errorf("%s:%s is not a group member", localHostname, localPort)
	}

	idxMemberState := res.Map("MEMBER_STATE")
	localMemberState := rows[0].Str(idxMemberState)
	return localMemberState, nil
}

// getGroupMembers returns a list of group members that have detected an anomaly.
func getGroupMembers(db *mysql.Conn, localHostname string, localPort string) ([]groupMember, error) {
	var groupMembers []groupMember

	stmt, err := (*db).Prepare(`
SELECT MEMBER_HOST, MEMBER_PORT, MEMBER_STATE 
FROM   performance_schema.replication_group_members 
WHERE  MEMBER_STATE NOT IN ( 'ONLINE', 'RECOVERING' ) 
       AND NOT ( MEMBER_HOST = ? AND MEMBER_PORT = ? )
ORDER  BY MEMBER_HOST;
`)
	if err != nil {
		return groupMembers, fmt.Errorf("couldn't execute query")
	}

	rows, res, err := stmt.Exec(localHostname, localPort)
	if err != nil {
		return groupMembers, fmt.Errorf("couldn't execute query")
	}

	idxMemberHost := res.Map("MEMBER_HOST")
	idxMemberPort := res.Map("MEMBER_PORT")
	idxMemberState := res.Map("MEMBER_STATE")
	for _, row := range rows {
		memberHost := fmt.Sprintf("%s:%s", row.Str(idxMemberHost), row.Str(idxMemberPort))
		groupMembers = append(
			groupMembers,
			groupMember{
				Host:  memberHost,
				State: row.Str(idxMemberState),
			})
	}
	return groupMembers, nil
}

func checkGroupReplication(args []string) *checkers.Checker {
	opts := groupReplicationOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	psr.Usage = "group-replication [OPTIONS]"
	_, err := psr.ParseArgs(args)
	if err != nil {
		os.Exit(1)
	}
	db := newMySQL(opts.mysqlSetting)
	err = db.Connect()
	if err != nil {
		return checkers.Unknown("couldn't connect DB")
	}
	defer db.Close()

	localMemberState, err := getLocalMemberState(&db, opts.LocalHostname, opts.LocalPort)
	if err != nil {
		return checkers.Unknown(err.Error())
	}
	checkSt := checkers.OK
	msg := fmt.Sprintf(localMemberState)
	switch localMemberState {
	case stateOnline:
	case stateRecovering:
		checkSt = checkers.WARNING
	default:
		checkSt = checkers.CRITICAL
	}

	if !opts.GroupMember {
		return checkers.NewChecker(checkSt, msg)
	}

	groupMembers, err := getGroupMembers(&db, opts.LocalHostname, opts.LocalPort)
	if err != nil {
		return checkers.Unknown(err.Error())
	}

	if len(groupMembers) > 0 {
		if checkSt == checkers.OK {
			checkSt = checkers.WARNING
		}
		var groupMembersList []string
		for _, member := range groupMembers {
			groupMembersList = append(
				groupMembersList,
				fmt.Sprintf("%s %s", member.Host, member.State))
		}
		groupMembersState := strings.Join(groupMembersList, ", ")
		msg = fmt.Sprintf("%s. Anomalies were detected in other group members: %s", localMemberState, groupMembersState)
	}

	return checkers.NewChecker(checkSt, msg)
}
