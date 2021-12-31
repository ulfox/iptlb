package log

var (
	// ErrFlagReset when reset used together with -src-addr || -dest-addr or both
	ErrFlagReset = "both --delete and --reset options were provided. Only one can be used"

	// ErrInvalidIPV4 when an invalid ipv4 is given as input
	ErrInvalidIPV4 = "IP [%s] is not a vlaid ipv4"

	// ErrProfileNotExist when a profile does not exist in the state file
	ErrProfileNotExist = "profile [%s] does not exist"

	// ErrKeyAlreadyExists when a key already exists in the state db
	ErrKeyAlreadyExists = "profile [%s] already defined. " +
		"Either use a new profile adding --profile=profileName" +
		", or reset this one with --reset --profile=%s"

	// ErrSourceAlreadyExists when a -src-addr already exists in the state db on any profile
	ErrSourceAlreadyExists = "source [%s] already defined on profile [%s]. " +
		"\nTo fix this you can, " +
		"either re-create this profile using different -src-addr, \n" +
		"or delete the profile [%s] with --delete --profile=%s"

	// ErrChainNotFound when we can not get a chain after the creation
	ErrChainNotFound = "Table[%s]/Chain[%s] not in the list"

	// WarnDelete issue warning when --delete flag is set
	WarnDelete = "Delete has been enabled. Deleting rules from profile [%s]"

	// WarnReset issue warning when --reset flag is set
	WarnReset = "Reset has been enabled. Resetting rules from profile [%s]"

	// InfoInputValidation info for successful validation
	InfoInputValidation = "Inputs validated successfuly"

	// InfoProfileCFG when profile configuration finished successfully
	InfoProfileCFG = "Done configuring profile [%s]"

	// InfoProfileDelete when profile deletion finished successfully
	InfoProfileDelete = "Done cleaning profile [%s]"

	// InfoInsertRuleAlreadyExists when inserting a new rule but it already exists
	InfoInsertRuleAlreadyExists = "[Insert] Rule: [%s] at [%d] exists on table[%s]/chain[%s]"

	// InfoInsertRule when inserting a new rule
	InfoInsertRule = "[Insert] Rule: [%s] at [%d] on table[%s]/chain[%s]"

	// InfoAppendRuleAlreadyExists when appending a new rule but it already exists
	InfoAppendRuleAlreadyExists = "[Append] Rule: [%s] exists on table[%s]/chain[%s]"

	// InfoAppendRule when appending a new rule
	InfoAppendRule = "[Append] Rule: [%s] on table[%s]/chain[%s]"

	// InfoDeleteRule when deleting a rule
	InfoDeleteRule = "[Deleted] Rule: [%s] table[%s]/chain[%s]"

	// InfoDoneChainCFG when we complete the update of a chain
	InfoDoneChainCFG = "Done configuring table[%s]/chain[%s]"

	// InfoChainDoesNotExist when we check if a chain exists
	InfoChainDoesNotExist = "Chain [%s] on table [%s] does not exist. Creating..."

	// InfoChainFound when a chain exists
	InfoChainFound = "Chain [%s] on table [%s] found"

	// InfoChainLoggingEnabled when logging is enabled for a chain
	InfoChainLoggingEnabled = "Enabled logging to chain %s"
)
