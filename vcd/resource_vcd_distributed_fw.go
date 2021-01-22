package vcd

//lint:file-ignore SA1019 ignore deprecated functions
import (
	"fmt"
	"log"
	"sort"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lmicke/go-vcloud-director/v2/govcd"
)

var appliedResource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Name of the Firewall Object",
		},
		"value": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Identifier of affected Object",
		},
		"type": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Type of affected Object, ex. SG, VM,",
		},
		"is_valid": {
			Type:     schema.TypeBool,
			Computed: true,
		},
	},
}

var ruleResource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"order": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "Order of Firewall Rules from bottom to top",
		},
		"action": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Action of the Firewall: allow, deny",
		},
		"applied_to": {
			Type: schema.TypeSet,
			Elem: appliedResource,
		},
		"direction": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Direction of Firewall Rule",
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the Firewall Rule",
		},
		"disabled": {
			Type:     schema.TypeBool,
			Default:  false,
			Optional: true,
		},
		"logged": {
			Type:     schema.TypeBool,
			Default:  false,
			Optional: true,
		},
		"packet_type": {
			Type:     schema.TypeString,
			Default:  "any",
			Optional: true,
		},
	},
}

func resourceVcdVdcDFW() *schema.Resource {

	return &schema.Resource{
		Create: resourceVcdDFWCreate,
		Delete: resourceVcdDFWDelete,
		Read:   resourceVcdDFWRead,
		Update: resourceVcdDFWUpdate,

		Schema: map[string]*schema.Schema{
			"priority": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Description: "The name of organization to use, optional if defined at provider " +
					"level. Useful when connected as sysadmin working across different organizations",
			},
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			"vdc_id": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the VDC",
			},
			"type": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
			},
			"rule": {
				Type: schema.TypeSet,
				Elem: ruleResource,
			},
		},
	}
}

// Creates a new VDC from a resource definition
func resourceVcdDFWCreate(d *schema.ResourceData, meta interface{}) error {
	orgVdcName := d.Get("name").(string)
	log.Printf("[TRACE] VDCDF creation initiated: %s", orgVdcName)

	vcdClient := meta.(*VCDClient)

	if !vcdClient.Client.IsSysAdmin {
		return fmt.Errorf("functionality requires System administrator privileges")
	}
	// VDC creation is accessible only in administrator API part
	//adminOrg, err := vcdClient.GetAdminOrgFromResource(d)
	//if err != nil {
	//	return fmt.Errorf(errorRetrievingOrg, err)
	//}

	//Init VDCDWF Object
	dfw := govcd.NewDFW(&vcdClient.Client)

	//Enable DFW, doesnt matter if it is already enabled.
	url, err := dfw.EnableDistributedFirewall(d.Get("vdc_id").(string))
	log.Printf("[DEBUG] TF: Distributed Firewall URL: %s", url)
	log.Printf("[DEBUG] %v", dfw.Client)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Distributed Firewall enabled.")

	firewallEnabled, err := dfw.CheckDistributedFirewall(d.Get("vdc_id").(string))
	if err != nil {
		return err
	}
	if !firewallEnabled {
		return fmt.Errorf("Distributed Firewall is not enabled.")
	}
	log.Printf("[DEBUG] XML-Response: %+v\n", dfw.Section)

	//Change Fields:
	dfw, err = changeFirewallRules(d, dfw)
	if err != nil {
		return err
	}

	err = dfw.UpdateDistributedFirewall(d.Get("vdc_id").(string))
	if err != nil {
		return err
	}

	d.SetId(strconv.Itoa(dfw.Section.ID))

	return resourceVcdDFWRead(d, meta)
}

// Fetches information about an existing VDC for a data definition
func resourceVcdDFWRead(d *schema.ResourceData, meta interface{}) error {
	vcdClient := meta.(*VCDClient)
	//Init VDCDWF Object
	dfw := govcd.NewDFW(&vcdClient.Client)

	firewallEnabled, err := dfw.CheckDistributedFirewall(d.Get("vdc_id").(string))
	if err != nil {
		return err
	}
	if !firewallEnabled {
		return fmt.Errorf("Distributed Firewall is not enabled.")
	}

	_ = d.Set("type", dfw.Section.Type)

	rules := dfw.Section.Rules
	var ruleList []interface{}
	for _, rule := range rules {
		ruleMap := make(map[string]interface{})
		// Does Order get Set Perhaps ToDo
		ruleMap["action"] = rule.Action
		ruleMap["name"] = rule.Name
		ruleMap["direction"] = rule.Direction
		ruleMap["packet_type"] = rule.PacketType
		ruleMap["disabled"] = rule.Disabled
		ruleMap["logged"] = rule.Logged

		// Applied_to_set
		var appliedList []interface{}

		for _, applied := range rule.AppliedToList {
			appliedMap := make(map[string]interface{})

			appliedMap["name"] = applied.ID.Name
			appliedMap["value"] = applied.ID.Value
			appliedMap["type"] = applied.ID.Type
			appliedMap["is_valid"] = applied.ID.IsValid

			appliedList = append(appliedList, appliedMap)
		}
		appliedSet := schema.NewSet(schema.HashResource(appliedResource), appliedList)
		ruleMap["applied_to"] = appliedSet

		ruleList = append(ruleList, ruleMap)
	}
	ruleSet := schema.NewSet(schema.HashResource(ruleResource), ruleList)
	err = d.Set("rule", ruleSet)
	if err != nil {
		return fmt.Errorf("[distributed Firewall read]  could not set rules block: %s", err)
	}

	return nil
}

//resourceVcdVdcUpdate function updates resource with found configurations changes
func resourceVcdDFWUpdate(d *schema.ResourceData, meta interface{}) error {

	return resourceVcdDFWCreate(d, meta)
}

// Deletes a VDC, optionally removing all objects in it as well
func resourceVcdDFWDelete(d *schema.ResourceData, meta interface{}) error {
	vcdClient := meta.(*VCDClient)
	//Init VDCDWF Object
	dfw := govcd.NewDFW(&vcdClient.Client)

	err := dfw.DeleteDistributedFirewall(d.Get("vdc_id").(string))
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}

func changeFirewallRules(d *schema.ResourceData, dfw *govcd.DFW) (*govcd.DFW, error) {
	rules, ok := d.Get("rule").(*schema.Set)
	if !ok {
		return dfw, fmt.Errorf("[DEBUG] Unsupported Type: %T\n", rules)
	}

	ruleList := rules.List()

	//Get and Set Rules
	var rulemap map[int]govcd.DFWRule
	rulemap = make(map[int]govcd.DFWRule)
	for _, value := range ruleList {
		rule := govcd.DFWRule{}
		ruleValues := value.(map[string]interface{})

		// Set it all
		rule.Action = ruleValues["action"].(string)
		rule.Name = ruleValues["name"].(string)
		rule.Direction = ruleValues["direction"].(string)
		rule.PacketType = ruleValues["packet_type"].(string)
		rule.Disabled = ruleValues["disabled"].(bool)
		rule.Logged = ruleValues["logged"].(bool)

		appliedTo := ruleValues["applied_to"].(*schema.Set)
		if !ok {
			return dfw, fmt.Errorf("[DEBUG] Unsupported Type: %T\n", rules)
		}
		appliedList := appliedTo.List()

		var dfwAppliedTo []govcd.DFWApplied

		for _, value := range appliedList {
			appliedStruct := govcd.DFWApplied{}
			appliedValues := value.(map[string]interface{})

			//Set applied_Settings
			appliedStruct.Name = appliedValues["name"].(string)
			appliedStruct.Value = appliedValues["value"].(string)
			appliedStruct.Type = appliedValues["type"].(string)

			dfwAppliedTo = append(dfwAppliedTo, appliedStruct)
		}

		rulemap[ruleValues["priority"].(int)] = rule

	}

	//Sort Firewall Rules by priority and insert into DFW
	keys := make([]int, len(rulemap))
	i := 0
	for k := range rulemap {
		keys[i] = k
		i++
	}
	sort.Ints(keys)

	sortedRules := make([]govcd.DFWRule, len(rulemap))
	for key, value := range keys {
		sortedRules[key] = rulemap[value]
	}
	for _, value := range sortedRules {
		dfw.Section.Rules = append(dfw.Section.Rules, value)
	}

	return dfw, nil
}
