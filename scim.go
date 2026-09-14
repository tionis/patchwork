package main

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/tionis/patchwork/internal/auth"
)

// registerSCIMRoutes wires minimal RFC 7644 Users and Groups provisioning.
// It is an optional capability: with SCIM disabled no routes exist at all.
func (s *server) registerSCIMRoutes(router *mux.Router) {
	if !s.scimEnabled {
		return
	}

	router.HandleFunc("/scim/v2/Users", s.metricsMiddleware("scim", s.handleSCIMUsers))
	router.HandleFunc("/scim/v2/Users/{id}", s.metricsMiddleware("scim", s.handleSCIMUser))
	router.HandleFunc("/scim/v2/Groups", s.metricsMiddleware("scim", s.handleSCIMGroups))
	router.HandleFunc("/scim/v2/Groups/{id}", s.metricsMiddleware("scim", s.handleSCIMGroup))
}

var scimFilterPattern = regexp.MustCompile(`^([A-Za-z]+)\s+eq\s+"((?:[^"\\]|\\.)*)"$`)

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  strconv.Itoa(status),
	})
}

func writeSCIMJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func decodeSCIMJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(dst); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "Request body must be a single JSON value.")
		return false
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeSCIMError(w, http.StatusBadRequest, "Request body must be a single JSON value.")
		return false
	}

	return true
}

// checkSCIMAuth validates the provisioner bearer token.
func (s *server) checkSCIMAuth(w http.ResponseWriter, r *http.Request) bool {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") ||
		!hmac.Equal([]byte(fields[1]), s.scimToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		writeSCIMError(w, http.StatusUnauthorized, "Authentication required.")
		return false
	}

	return true
}

func scimUserResource(user *auth.User) map[string]any {
	resource := map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":       user.ID,
		"userName": user.ID,
		"active":   user.Active,
		"meta":     map[string]any{"resourceType": "User"},
	}
	if user.DisplayName != "" {
		resource["displayName"] = user.DisplayName
	}

	if user.SCIMID != "" {
		resource["externalId"] = user.SCIMID
	}

	return resource
}

func scimGroupResource(group *auth.Group) map[string]any {
	members := make([]any, 0, len(group.Members))
	for _, member := range group.Members {
		members = append(members, map[string]any{"value": member, "display": member})
	}

	resource := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"id":          group.ID,
		"displayName": group.DisplayName,
		"members":     members,
		"meta":        map[string]any{"resourceType": "Group"},
	}
	if group.SCIMID != "" {
		resource["externalId"] = group.SCIMID
	}

	return resource
}

func scimList(resources []any, startIndex, count int) map[string]any {
	if startIndex < 1 {
		startIndex = 1
	}

	total := len(resources)

	if count <= 0 {
		count = total
	}

	start := min(startIndex-1, total)
	end := min(start+count, total)

	return map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": end - start,
		"Resources":    resources[start:end],
	}
}

func scimQueryInt(values map[string][]string, key string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(strings.Join(values[key], "")))
	return n
}

func (s *server) handleSCIMUsers(w http.ResponseWriter, r *http.Request) {
	if !s.checkSCIMAuth(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		queries := r.URL.Query()
		filter := strings.TrimSpace(queries.Get("filter"))

		users, err := s.authStore.ListUsers()
		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		resources := make([]any, 0, len(users))

		for i := range users {
			if !scimUserMatches(&users[i], filter) {
				continue
			}

			resources = append(resources, scimUserResource(&users[i]))
		}

		writeSCIMJSON(w, http.StatusOK, scimList(resources,
			scimQueryInt(queries, "startIndex"), scimQueryInt(queries, "count")))

	case http.MethodPost:
		var body struct {
			UserName    string `json:"userName"`
			DisplayName string `json:"displayName"`
			ExternalID  string `json:"externalId"`
			Active      *bool  `json:"active"`
		}
		if !decodeSCIMJSON(w, r, &body) {
			return
		}

		if strings.TrimSpace(body.UserName) == "" {
			writeSCIMError(w, http.StatusBadRequest, "userName is required.")
			return
		}

		active := true
		if body.Active != nil {
			active = *body.Active
		}

		user, err := s.authStore.CreateUserWithIdentity(
			body.UserName, body.DisplayName, false, active, "", body.ExternalID,
		)
		if errors.Is(err, auth.ErrExists) {
			writeSCIMError(w, http.StatusConflict, "User already exists.")
			return
		}

		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.audit(r, "scim", "user.create", user.ID, "ok")
		writeSCIMJSON(w, http.StatusCreated, scimUserResource(user))

	default:
		w.Header().Set("Allow", "GET, POST")
		writeSCIMError(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

// scimUserMatches applies the standard `attr eq "value"` filter for the
// attributes Authentik reconciles on. Unknown filters match nothing rather
// than everything.
func scimUserMatches(user *auth.User, filter string) bool {
	if filter == "" {
		return true
	}

	parts := scimFilterPattern.FindStringSubmatch(filter)
	if parts == nil {
		return false
	}

	switch strings.ToLower(parts[1]) {
	case "username":
		return user.ID == parts[2]
	case "externalid":
		return user.SCIMID != "" && user.SCIMID == parts[2]
	default:
		return false
	}
}

func (s *server) handleSCIMUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkSCIMAuth(w, r) {
		return
	}

	id := mux.Vars(r)["id"]

	switch r.Method {
	case http.MethodGet:
		user, err := s.authStore.GetUser(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "User not found.")
			return
		}

		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeSCIMJSON(w, http.StatusOK, scimUserResource(user))

	case http.MethodPut:
		var body struct {
			UserName    string `json:"userName"`
			DisplayName string `json:"displayName"`
			ExternalID  string `json:"externalId"`
			Active      *bool  `json:"active"`
		}
		if !decodeSCIMJSON(w, r, &body) {
			return
		}

		if body.UserName != "" && body.UserName != id {
			writeSCIMError(w, http.StatusBadRequest, "userName is immutable.")
			return
		}

		user, err := s.applySCIMUserReplace(id, body.DisplayName, body.ExternalID, body.Active)
		if errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "User not found.")
			return
		}
		if errors.Is(err, auth.ErrLastAdmin) {
			writeSCIMError(w, http.StatusConflict, "Refusing to remove the last active admin.")
			return
		}

		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.audit(r, "scim", "user.replace", id, "ok")
		writeSCIMJSON(w, http.StatusOK, scimUserResource(user))

	case http.MethodPatch:
		var body struct {
			Operations []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			} `json:"Operations"`
		}
		if !decodeSCIMJSON(w, r, &body) {
			return
		}

		var patch auth.UserPatch

		for _, operation := range body.Operations {
			if !strings.EqualFold(operation.Op, "replace") {
				writeSCIMError(w, http.StatusBadRequest, "Only replace operations are supported.")
				return
			}

			switch strings.ToLower(strings.TrimSpace(operation.Path)) {
			case "displayname":
				value, ok := operation.Value.(string)
				if !ok {
					writeSCIMError(w, http.StatusBadRequest, "displayName must be a string.")
					return
				}
				patch.DisplayName = &value
			case "externalid":
				value, ok := operation.Value.(string)
				if !ok {
					writeSCIMError(w, http.StatusBadRequest, "externalId must be a string.")
					return
				}
				patch.SCIMID = &value
			case "active":
				value, ok := operation.Value.(bool)
				if !ok {
					writeSCIMError(w, http.StatusBadRequest, "active must be a boolean.")
					return
				}
				patch.Active = &value
			case "username", "id":
				writeSCIMError(w, http.StatusBadRequest, "userName is immutable.")
				return
			case "":
				writeSCIMError(w, http.StatusBadRequest, "Pathless replace is not supported.")
				return
			default:
				writeSCIMError(w, http.StatusBadRequest, "Unsupported path "+operation.Path+".")
				return
			}
		}

		updated, err := s.authStore.PatchUser(id, patch)
		if errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "User not found.")
			return
		}
		if errors.Is(err, auth.ErrLastAdmin) {
			writeSCIMError(w, http.StatusConflict, "Refusing to remove the last active admin.")
			return
		}
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.audit(r, "scim", "user.patch", id, "ok")
		writeSCIMJSON(w, http.StatusOK, scimUserResource(updated))

	case http.MethodDelete:
		// Deprovisioning deactivates: tokens stop validating while history
		// and audit rows are preserved.
		active := false
		_, err := s.authStore.PatchUser(id, auth.UserPatch{Active: &active})
		if errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "User not found.")
			return
		}
		if errors.Is(err, auth.ErrLastAdmin) {
			writeSCIMError(w, http.StatusConflict, "Refusing to remove the last active admin.")
			return
		}
		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.audit(r, "scim", "user.deactivate", id, "ok")
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		writeSCIMError(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

func (s *server) applySCIMUserReplace(id, displayName, externalID string, active *bool) (*auth.User, error) {
	return s.authStore.PatchUser(id, auth.UserPatch{
		DisplayName: &displayName,
		Active:      active,
		SCIMID:      &externalID,
	})
}

// scimGroupBody is the shared shape for group create/replace payloads.
type scimGroupBody struct {
	DisplayName string `json:"displayName"`
	ExternalID  string `json:"externalId"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (s *server) handleSCIMGroups(w http.ResponseWriter, r *http.Request) {
	if !s.checkSCIMAuth(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		queries := r.URL.Query()
		filter := strings.TrimSpace(queries.Get("filter"))

		groups, err := s.authStore.ListGroups()
		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		resources := make([]any, 0, len(groups))

		for i := range groups {
			if !scimGroupMatches(&groups[i], filter) {
				continue
			}

			resources = append(resources, scimGroupResource(&groups[i]))
		}

		writeSCIMJSON(w, http.StatusOK, scimList(resources,
			scimQueryInt(queries, "startIndex"), scimQueryInt(queries, "count")))

	case http.MethodPost:
		var body scimGroupBody
		if !decodeSCIMJSON(w, r, &body) {
			return
		}

		if strings.TrimSpace(body.DisplayName) == "" {
			writeSCIMError(w, http.StatusBadRequest, "displayName is required.")
			return
		}

		members := make([]string, 0, len(body.Members))
		for _, member := range body.Members {
			resolved, err := s.resolveSCIMMember(member.Value)
			if err != nil {
				writeSCIMError(w, http.StatusBadRequest, err.Error())
				return
			}

			members = append(members, resolved)
		}

		group, err := s.authStore.UpsertGroupWithMembers(
			scimGroupID(body), body.DisplayName, body.ExternalID, members,
		)
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.audit(r, "scim", "group.create", group.ID, "ok")
		writeSCIMJSON(w, http.StatusCreated, scimGroupResource(group))

	default:
		w.Header().Set("Allow", "GET, POST")
		writeSCIMError(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

// scimGroupID derives a stable local id: the provider's externalId when
// present, otherwise a slug of the display name.
func scimGroupID(body scimGroupBody) string {
	if strings.TrimSpace(body.ExternalID) != "" {
		return body.ExternalID
	}

	slug := strings.ToLower(strings.TrimSpace(body.DisplayName))
	slug = strings.Join(strings.Fields(slug), "-")

	return "grp-" + slug
}

func scimGroupMatches(group *auth.Group, filter string) bool {
	if filter == "" {
		return true
	}

	parts := scimFilterPattern.FindStringSubmatch(filter)
	if parts == nil {
		return false
	}

	switch strings.ToLower(parts[1]) {
	case "displayname":
		return group.DisplayName == parts[2]
	case "externalid":
		return group.SCIMID != "" && group.SCIMID == parts[2]
	default:
		return false
	}
}

// resolveSCIMMember maps a SCIM member value (username or user externalId)
// to a local user id.
func (s *server) resolveSCIMMember(value string) (string, error) {
	if _, err := s.authStore.GetUser(value); err == nil {
		return value, nil
	}

	if user, err := s.authStore.FindUserBySCIMID(value); err == nil {
		return user.ID, nil
	}

	return "", errors.New("unknown member " + strconv.Quote(value))
}

var scimMemberRemovePattern = regexp.MustCompile(`^members\[value\s+eq\s+"((?:[^"\\]|\\.)*)"\]$`)

func (s *server) handleSCIMGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkSCIMAuth(w, r) {
		return
	}

	id := mux.Vars(r)["id"]

	switch r.Method {
	case http.MethodGet:
		group, err := s.authStore.GetGroup(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "Group not found.")
			return
		}

		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeSCIMJSON(w, http.StatusOK, scimGroupResource(group))

	case http.MethodPut:
		var body scimGroupBody
		if !decodeSCIMJSON(w, r, &body) {
			return
		}

		if body.DisplayName == "" {
			writeSCIMError(w, http.StatusBadRequest, "displayName is required.")
			return
		}

		members := make([]string, 0, len(body.Members))
		for _, member := range body.Members {
			resolved, err := s.resolveSCIMMember(member.Value)
			if err != nil {
				writeSCIMError(w, http.StatusBadRequest, err.Error())
				return
			}

			members = append(members, resolved)
		}

		group, err := s.authStore.UpsertGroupWithMembers(id, body.DisplayName, body.ExternalID, members)
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.audit(r, "scim", "group.replace", id, "ok")
		writeSCIMJSON(w, http.StatusOK, scimGroupResource(group))

	case http.MethodPatch:
		var body struct {
			Operations []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			} `json:"Operations"`
		}
		if !decodeSCIMJSON(w, r, &body) {
			return
		}

		group, err := s.authStore.GetGroup(id)
		if errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "Group not found.")
			return
		}

		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		mutations := make([]auth.GroupMemberMutation, 0)

		for _, operation := range body.Operations {
			switch {
			case strings.EqualFold(operation.Op, "add") && strings.EqualFold(strings.TrimSpace(operation.Path), "members"):
				added, err := scimMemberValues(operation.Value)
				if err != nil {
					writeSCIMError(w, http.StatusBadRequest, err.Error())
					return
				}

				for _, value := range added {
					resolved, err := s.resolveSCIMMember(value)
					if err != nil {
						writeSCIMError(w, http.StatusBadRequest, err.Error())
						return
					}

					mutations = append(mutations, auth.GroupMemberMutation{UserID: resolved})
				}
			case strings.EqualFold(operation.Op, "remove"):
				removed := scimMemberRemovePattern.FindStringSubmatch(strings.TrimSpace(operation.Path))
				if removed == nil {
					writeSCIMError(w, http.StatusBadRequest, "Only member add/remove operations are supported.")
					return
				}

				resolved, err := s.resolveSCIMMember(removed[1])
				if err != nil {
					writeSCIMError(w, http.StatusBadRequest, err.Error())
					return
				}

				mutations = append(mutations, auth.GroupMemberMutation{UserID: resolved, Remove: true})
			default:
				writeSCIMError(w, http.StatusBadRequest, "Only member add/remove operations are supported.")
				return
			}
		}

		group, err = s.authStore.PatchGroupMembers(id, mutations)
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.audit(r, "scim", "group.patch", id, "ok")
		writeSCIMJSON(w, http.StatusOK, scimGroupResource(group))

	case http.MethodDelete:
		if err := s.authStore.DeleteGroup(id); errors.Is(err, auth.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "Group not found.")
			return
		} else if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.audit(r, "scim", "group.delete", id, "ok")
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		writeSCIMError(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

// scimMemberValues decodes the member list of an add operation, accepting
// both object and {members:[...]} shapes.
func scimMemberValues(value any) ([]string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("invalid members value")
	}

	var objects []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &objects); err != nil {
		return nil, errors.New("invalid members value")
	}

	values := make([]string, 0, len(objects))
	for _, object := range objects {
		if object.Value != "" {
			values = append(values, object.Value)
		}
	}

	return values, nil
}
