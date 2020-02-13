package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DisposaBoy/JsonConfigReader"
	"github.com/TomOnTime/utfutil"
)
func LoadProviderConfigs(fname string) (map[string]map[string]string, error) {
	var results = map[string]map[string]string{}
	dat, err := utfutil.ReadFile(fname, utfutil.POSIX)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("INFO: Config file %q does not exist. Skipping.\n", fname)
			return results, nil
		}
		return nil, fmt.Errorf("While reading provider credentials file %v: %v", fname, err)
	}
	s := string(dat)
	r := JsonConfigReader.New(strings.NewReader(s))
	err = json.NewDecoder(r).Decode(&results)
	if err != nil {
		return nil, fmt.Errorf("While parsing provider credentials file %v: %v", fname, err)
	}
	if err = replaceEnvVars(results); err != nil {
		return nil, err
	}
	return results, nil
}

func replaceEnvVars(m map[string]map[string]string) error {
	for _, keys := range m {
		for k, v := range keys {
			if strings.HasPrefix(v, "$") {
				env := v[1:]
				newVal := os.Getenv(env)
				keys[k] = newVal
			}
		}
	}
	return nil
}
