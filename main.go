package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CaliDog/certstream-go"
	"github.com/cheggaaa/pb/v3"
	"github.com/jmoiron/jsonq"

	logging "github.com/op/go-logging"
)

//from CaliDog, switch to method handler
var log = logging.MustGetLogger("example")

//main method
func main() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)
	tmpl := ` {{speed . "%s per second" | red }} `
	pbCount := 10000
	// start bar based on our template
	bar := pb.ProgressBarTemplate(tmpl).Start(pbCount)
	for {
		select {
		case jq := <-stream:
			messageType, err := jq.String("message_type")
			bar.Increment()
			if messageType == "certificate_update" {
				//get the array from the object containing the list of domains registered
				obj, err := jq.Array("data", "leaf_cert", "all_domains")
				if err != nil {
					log.Fatal("Error decoding jq obj")
				}
				//iterate through array of domains from single event
				for _, element := range obj {
					//send to scoring algorithm
					score := scoring(strings.ToLower(element.(string)))

					switch {
					case score >= 100:
						fmt.Println("\n[!] Suspicious: ", score, element.(string))

					case score >= 90:
						fmt.Println("\n[!] Suspicious: ", score, element.(string))

					case score >= 80:
						fmt.Println("\n[!] Likely: ", score, element.(string))

					case score >= 65:
						fmt.Println("\n[!] Potential: ", score, element.(string))
					}
				}
			}

			if err != nil {
				log.Fatal("Error decoding jq string")
			}

			//log.Info("Message type -> ", messageType)
			//log.Info("recv: ", jq)

		case err := <-errStream:
			log.Error(err)
		}
	}
}

/*scoring method
runs domains through check and returns a score */
func scoring(domain string) int {

	//try to parse through confusable chars
	//skele := confusables.Skeleton(domain)
	skele := domain

	//path to scoring file format is Jank.json
	absPath, err := filepath.Abs(`.\scoring.json`)
	check(err)
	f, err := os.Open(absPath) // replaced by abs path `C:\tmp\scoring.json`
	check(err)
	defer f.Close()

	//read the json data from the scoring file using jq
	data := map[string]interface{}{}
	dec := json.NewDecoder(f)
	dec.Decode(&data)
	jq := jsonq.NewQuery(data)

	//pull the keywords for scoring first
	list, err := jq.Array("keywords")
	check(err)

	//terms of the math equation, we are going to sum them for the score to pass back
	terms := make([]int, len(list))
	//try some concurrency, aint working rn
	//wg := sync.WaitGroup{}

	//iterate through the supicious words list and see if they are in the domain
	for i, element := range list {

		//split json array object into keyword and its score
		elSli := strings.Split(element.(string), ":")

		//pull comment lines out of the json file
		if !(string(elSli[0][0]) == "_") {

			//fucntion to offload search for keyword in domain
			if subSearch(skele, elSli[0]) {
				//set addition term to the score from the found keyword
				terms[i], err = strconv.Atoi(elSli[1])
				check(err)
			}
		}
	}

	//sum the terms after everything is set amd return the score
	sum := 0
	for _, n := range terms {
		sum += n
	}
	//fmt.Println(sum, skele) //DEBUG
	return sum
}

/*Function checks for a substring and returns a bool, used for concurency
can contain multiple styles of checks to find if the string exists or not*/
func subSearch(skdomain string, chk string) bool {
	if strings.Contains(skdomain, chk) {
		return true
	}
	return false
}

//error checking function for ease of handling
func check(e error) {
	if e != nil {
		panic(e)
	}
}
