package lua

import (
	"net/url"

	lua "github.com/yuin/gopher-lua"
)

// URLService provides URL encoding/decoding functionality to Lua scripts
type URLService struct{}

// NewURLService creates a new URL service
func NewURLService() *URLService {
	return &URLService{}
}

// Register adds the URL service to the Lua state
// Usage in Lua:
//
//	local encoded = url.encode("/C=US/ST=North Carolina")
func (s *URLService) Register(L *lua.LState) {
	mod := L.NewTable()
	L.SetField(mod, "encode", L.NewFunction(s.luaURLEncode))
	L.SetGlobal("url", mod)
}

func (s *URLService) luaURLEncode(L *lua.LState) int {
	value := L.CheckString(1)
	L.Push(lua.LString(url.PathEscape(value)))
	return 1
}
