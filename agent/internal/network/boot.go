package network

const RulesDropInPath = "/etc/systemd/system/wg-quick@kry0.service.d/krynodes-rules.conf"

func RulesDropIn(executable string) string {
	return "[Service]\nExecStartPre=" + executable + " network rules\n"
}
