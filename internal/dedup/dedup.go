package dedup

import "ioc-pipeline/internal/model"

func Process(iocs []model.IOC) []model.IOC {
	seen := make(map[string]bool)
	unique := []model.IOC{}

	for _, ioc := range iocs {
		if _, exists := seen[ioc.Value]; !exists {
			seen[ioc.Value] = true
			unique = append(unique, ioc)
		}
	}
	return unique
}
