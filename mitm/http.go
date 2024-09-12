package mitm

import (
	"fmt"
	"socks2https/context"
	"socks2https/handler/httphandler"
)

func HandleHTTPFragment(ctx *context.Context) error {
	for _, requestHandler := range httphandler.RequestHandlers {
		ctx.HTTPContext.Request, ctx.HTTPContext.Response = requestHandler(ctx.HTTPContext.Request, ctx)
	}

	if ctx.HTTPContext.Response == nil {
		resp, err := ctx.HTTPContext.HttpClient.Do(ctx.HTTPContext.Request)
		if err != nil {
			return fmt.Errorf("Writing Request Failed : %v", err)
		}
		ctx.HTTPContext.Response = resp
		for _, modifyResponse := range httphandler.ResponseHandlers {
			ctx.HTTPContext.Response = modifyResponse(ctx.HTTPContext.Response, ctx)
		}
	}
	return nil
}
