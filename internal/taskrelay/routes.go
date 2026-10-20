package taskrelay

// validRouteNames reports whether a routed listener names exactly one
// routing: routes "broker", or a list of distinct, well-formed names.
func validRouteNames(routes string, names []string) bool {
	if (routes != "" && routes != routesBroker) || (routes == routesBroker) == (len(names) != 0) {
		return false
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !safeName.MatchString(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// routeNames is a routed listener's route check: under broker routing any
// name of the given shape, otherwise only the listed names.
func routeNames(routes string, names []string, shape func(string) bool) func(string) bool {
	if routes == routesBroker {
		return shape
	}
	table := make(map[string]bool, len(names))
	for _, name := range names {
		table[name] = true
	}
	return func(name string) bool { return table[name] }
}
