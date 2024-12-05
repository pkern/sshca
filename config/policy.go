/*
Copyright © 2024 Philipp Kern <pkern@debian.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package config

import (
	"fmt"
	"os/user"
	"slices"
	"time"
)

type User struct {
	*user.User
}

func (u *User) GroupIds() ([]string, error) {
	if u.User.Uid != "" {
		return u.User.GroupIds()
	}
	return nil, nil
}

func LookupUser(username string) (*User, error) {
	u, err := user.Lookup(username)
	if err != nil {
		// Create a stub no local user is found.
		return &User{User: &user.User{Username: username}}, nil
	}
	return &User{User: u}, nil
}

type Policy interface {
	ForUser(user *User) UserPolicy
}

type UserPolicy interface {
	CanIssueFor(username string, duration time.Duration) bool
}

// AdminOnlyPolicy allows everyone in group "adm" to issue certificates for
// the "root" user - in addition to allowing everyone is issue for themselves.
type AdminOnlyPolicy struct{}

func (AdminOnlyPolicy) ForUser(user *User) UserPolicy {
	return (*adminOnlyPolicyUser)(user)
}

type adminOnlyPolicyUser User

func groups(u *user.User) ([]string, error) {
	ids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("could not lookup groups for %q: %w", u.Name, err)
	}
	var groups []string
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			groups = append(groups, g.Name)
		}
	}
	return groups, nil
}

const maxLifetimeHours = 20

func (u *adminOnlyPolicyUser) CanIssueFor(username string, duration time.Duration) bool {
	if duration.Hours() > maxLifetimeHours {
		return false
	}
	if username == u.Username {
		return true
	}
	if username != "root" {
		return false
	}
	groups, _ := groups(u.User)
	return slices.Contains(groups, "adm")
}
