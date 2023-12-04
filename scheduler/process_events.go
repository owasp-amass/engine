package scheduler

import (
	"github.com/owasp-amass/engine/types"
)

func processEvent(e *types.Event) {
	sc := e.Sched.(*Scheduler)

	switch e.Type {
	case types.EventTypeAsset:
		edata := e.Data.(*types.AssetData)
		ap, err := sc.r.GetPipeline(edata.OAMType)
		if err != nil {
			return
		}

		if ede := sc.r.NewEventDataElement(e); ede != nil {
			ap.Queue.Append(ede)
			if element := <-ede.Ch; element != nil {
				state := types.EventStateDone

				if err := element.Error; err != nil {
					sc.logger.Printf("%s: %v", e.Name, err)
					state = types.EventStateError
				}

				SetEventState(e, state)
			}
		}
	case types.EventTypeSystem, types.EventTypeCustom:
		if e.Action != nil {
			if err := e.Action(e); err != nil {
				sc.logger.Printf("%s: %v", e.Name, err)
			}
		}
	case types.EventTypeLog:
		// Assuming you have a logger setup, for demonstration:
		sc.logger.Printf("LOG EVENT: %s\n", e.Name)
		SetEventState(e, types.EventStateDone)
	}
}
