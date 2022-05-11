/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"

	"gitee.com/zhaochuninhefei/fabric-ca-gm/cmd/fabric-ca-client/command"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

// The fabric-ca client main
func main() {
	initZcgolog()
	if err := command.RunMain(os.Args); err != nil {
		os.Exit(1)
	}
}

func initZcgolog() {
	zcgologConf := &zclog.Config{
		LogFileDir:        "/logs",
		LogFileNamePrefix: "fabric-ca-client-zcgolog",
		LogLevelGlobal:    zclog.LOG_LEVEL_INFO,
		LogMod:            zclog.LOG_MODE_LOCAL,
	}
	zclog.InitLogger(zcgologConf)
}
