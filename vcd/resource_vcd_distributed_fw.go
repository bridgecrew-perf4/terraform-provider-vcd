package vcd

//lint:file-ignore SA1019 ignore deprecated functions
import (
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lmicke/go-vcloud-director/v2/govcd"
)

func resourceVcdVdcDFW() *schema.Resource {

	return &schema.Resource{
		Create: resourceVcdDFWCreate,
		Delete: resourceVcdDFWDelete,
		Read:   resourceVcdDFWRead,
		Update: resourceVcdDFWUpdate,

		Schema: map[string]*schema.Schema{
			"org": {
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
