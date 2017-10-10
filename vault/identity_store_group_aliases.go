package vault

import (
	"fmt"
	"strings"

	"github.com/golang/protobuf/ptypes"
	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func groupAliasPaths(i *IdentityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "group-alias$",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the group alias.",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Alias of the group.",
				},
				"mount_accessor": {
					Type:        framework.TypeString,
					Description: "Mount accessor to which this alias belongs to.",
				},
				"group_id": {
					Type:        framework.TypeString,
					Description: "ID of the group to which this is an alias.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.checkPremiumVersion(i.pathGroupAliasRegister),
			},

			HelpSynopsis:    strings.TrimSpace(groupAliasHelp["group-alias"][0]),
			HelpDescription: strings.TrimSpace(groupAliasHelp["group-alias"][1]),
		},
		{
			Pattern: "group-alias/id/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the group alias.",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Alias of the group.",
				},
				"mount_accessor": {
					Type:        framework.TypeString,
					Description: "Mount accessor to which this alias belongs to.",
				},
				"group_id": {
					Type:        framework.TypeString,
					Description: "ID of the group to which this is an alias.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.checkPremiumVersion(i.pathGroupAliasIDUpdate),
				logical.ReadOperation:   i.checkPremiumVersion(i.pathGroupAliasIDRead),
				logical.DeleteOperation: i.checkPremiumVersion(i.pathGroupAlaisIDDelete),
			},

			HelpSynopsis:    strings.TrimSpace(groupAliasHelp["group-alias-by-id"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-alias-by-id"][1]),
		},
		{
			Pattern: "group-alias/id/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: i.checkPremiumVersion(i.pathGroupAliasIDList),
			},

			HelpSynopsis:    strings.TrimSpace(entityHelp["group-alias-id-list"][0]),
			HelpDescription: strings.TrimSpace(entityHelp["group-alias-id-list"][1]),
		},
	}
}

func (i *IdentityStore) pathGroupAliasRegister(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, ok := d.GetOk("id")
	if ok {
		return i.pathGroupAliasIDUpdate(req, d)
	}

	i.groupLock.Lock()
	defer i.groupLock.Unlock()

	return i.handleGroupAliasUpdateCommon(req, d, nil)
}

func (i *IdentityStore) pathGroupAliasIDUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	groupAliasID := d.Get("id").(string)
	if groupAliasID == "" {
		return logical.ErrorResponse("empty group alias ID"), nil
	}

	i.groupLock.Lock()
	defer i.groupLock.Unlock()

	groupAlias, err := i.memDBGroupAliasByID(groupID, true)
	if err != nil {
		return nil, err
	}
	if groupAlias == nil {
		return logical.ErrorResponse("invalid group alias ID"), nil
	}

	return i.handleGroupAliasUpdateCommon(req, d, groupAlias)
}

func (i *IdentityStore) handleGroupAliasUpdateCommon(req *logical.Request, d *framework.FieldData, groupAlias *identity.GroupAlias) (*logical.Response, error) {
	var err error
	var newGroupAlias bool
	var group *identity.Group
	var previousGroup *identity.Group

	// groupAlias will be nil when a new alias is being registered; create a
	// new struct in that case.
	if groupAlias == nil {
		groupAlias = &identity.GroupAlias{}
		newGroupAlias = true
	}

	// Get entity id
	groupID := d.Get("group_id").(string)
	if groupID != "" {
		group, err = i.memDBGroupByID(groupID, true)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return logical.ErrorResponse("invalid group ID"), nil
		}
	}

	// Get group alias name
	groupAliasName := d.Get("name").(string)
	if groupAliasName == "" {
		return logical.ErrorResponse("missing alias name"), nil
	}

	mountAccessor := d.Get("mount_accessor").(string)
	if mountAccessor == "" {
		return logical.ErrorResponse("missing mount_accessor"), nil
	}

	mountValidationResp := i.validateMountAccessorFunc(mountAccessor)
	if mountValidationResp == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid mount accessor %q", mountAccessor)), nil
	}

	groupAliasByFactors, err := i.memDBGroupAliasByFactors(mountValidationResp.MountAccessor, groupAliasName, false)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	if newGroupAlias {
		if groupAliasByFactors != nil {
			return logical.ErrorResponse("combination of mount and group alias name is already in use"), nil
		}

		// If this is an alias being tied to a non-existent group, create
		// a new group for it.
		if group == nil {
			group = &identity.Group{
				Alias: *identity.GroupAlias{
					groupAlias,
				},
			}
		} else {
			group.Alias = groupAlias
		}
	} else {
		// Verify that the combination of group alias name and mount is not
		// already tied to a different alias
		if groupAliasByFactors != nil && groupAliasByFactors.ID != groupAlias.ID {
			return logical.ErrorResponse("combination of mount and group alias name is already in use"), nil
		}

		// Fetch the group to which the alias is tied to
		existingGroup, err := i.memDBGroupByAliasID(groupAlias.ID, true)
		if err != nil {
			return nil, err
		}

		if existingGroup == nil {
			return nil, fmt.Errorf("group alias is not associated with a group")
		}

		if group != nil && group.ID != existingGroup.ID {
			// Alias should be transferred from 'existingGroup' to 'group'
			err = i.deleteAliasFromGroup(existingGroup, groupAlias)
			if err != nil {
				return nil, err
			}
			previousGroup = existingGroup
			group.Alias = append(group.Alias, groupAlias)
			resp.AddWarning(fmt.Sprintf("group alias is being transferred from group %q to %q", existingGroup.ID, group.ID))
		} else {
			// Update group with modified alias
			err = i.updateAliasInGroup(existingGroup, groupAlias)
			if err != nil {
				return nil, err
			}
			group = existingGroup
		}
	}

	// ID creation and other validations; This is more useful for new entities
	// and may not perform anything for the existing entities. Placing the
	// check here to make the flow common for both new and existing entities.
	err = i.sanitizeGroup(group)
	if err != nil {
		return nil, err
	}

	// Update the fields
	groupAlias.Name = groupAliasName
	groupAlias.MountType = mountValidationResp.MountType
	groupAlias.MountAccessor = mountValidationResp.MountAccessor
	groupAlias.GroupID = group.ID

	// ID creation and other validations
	err = i.sanitizeGroupAlias(groupAlias)
	if err != nil {
		return nil, err
	}

	// Index group and its alias in MemDB and persist group along with
	// alias in storage. If the group alias is being transferred over from
	// one group to another, previous group needs to get refreshed in MemDB
	// and persisted in storage as well.
	err = i.upsertGroup(group, previousGroup, true)
	if err != nil {
		return nil, err
	}

	// Return IDs of both group alias and entity
	resp.Data = map[string]interface{}{
		"id":       groupAlias.ID,
		"group_id": group.ID,
	}

	return resp, nil
}

// pathGroupAliasIDRead returns the properties of an alias for a given
// alias ID
func (i *IdentityStore) pathGroupAliasIDRead(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	groupAliasID := d.Get("id").(string)
	if groupAliasID == "" {
		return logical.ErrorResponse("empty group alias id"), nil
	}

	groupAlias, err := i.memDBGroupAliasByID(groupAliasID, false)
	if err != nil {
		return nil, err
	}

	if groupAlias == nil {
		return nil, nil
	}

	respData := map[string]interface{}{}
	respData["id"] = groupAlias.ID
	respData["name"] = alias.Name
	respData["group_id"] = group.EntityID
	respData["mount_type"] = alias.MountType
	respData["mount_accessor"] = alias.MountAccessor

	// Convert protobuf timestamp into RFC3339 format
	respData["creation_time"] = ptypes.TimestampString(alias.CreationTime)
	respData["last_update_time"] = ptypes.TimestampString(alias.LastUpdateTime)

	return &logical.Response{
		Data: respData,
	}, nil
}

// pathGroupAliasIDDelete deletes the group's alias for a given group alias ID
func (i *IdentityStore) pathAliasIDDelete(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	groupAliasID := d.Get("id").(string)
	if groupAliasID == "" {
		return logical.ErrorResponse("missing group alias ID"), nil
	}

	return nil, i.deleteGroupAlias(groupAliasID)
}

// pathGroupAliasIDList lists the IDs of all the valid group aliases in the
// identity store
func (i *IdentityStore) pathGroupAliasIDList(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ws := memdb.NewWatchSet()
	iter, err := i.memDBGroupAliases(ws)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch iterator for group aliases in memdb: %v", err)
	}

	var groupAliasIDs []string
	for {
		raw := iter.Next()
		if raw == nil {
			break
		}
		groupAliasIDs = append(groupAliasIDs, raw.(*identity.GroupAlias).ID)
	}

	return logical.ListResponse(groupAliasIDs), nil
}

var groupAliasHelp = map[string][2]string{
	"group-alias": {
		"Creates a new group alias, or updates an existing one.",
		"",
	},
	"group-alias-id": {
		"Update, read or delete a group alias using ID.",
		"",
	},
	"group-alias-id-list": {
		"List all the entity IDs.",
		"",
	},
}
