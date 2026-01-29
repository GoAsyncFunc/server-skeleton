package service

import (
	"fmt"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trojan"
)

// buildUser converts API user info to Xray protocol users.
// IMPORTANT: This is an EXAMPLE implementation for TROJAN.
// Developers MUST replace this with logic suitable for their target protocol.
func buildUser(tag string, userInfo []api.UserInfo) (users []*protocol.User) {
	// =================================================================================
	// [EXAMPLE START] Trojan User Conversion
	// Replace the code below with your protocol-specific logic.
	// =================================================================================

	for _, user := range userInfo {
		// Trojan uses a password (which we map to user.Uuid here).
		trojanAccount := &trojan.Account{
			Password: user.Uuid,
		}
		account := serial.ToTypedMessage(trojanAccount)
		u := &protocol.User{
			Level:   0,
			Email:   buildUserEmail(tag, user.Id, user.Uuid),
			Account: account,
		}
		users = append(users, u)
	}

	// =================================================================================
	// [EXAMPLE END]
	// =================================================================================

	return users
}

func buildUserEmail(tag string, uid int, uuid string) string {
	return fmt.Sprintf("%s|%d|%s", tag, uid, uuid)
}
