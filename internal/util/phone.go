package util

import "strings"

// NormalizePhone normalizes phone numbers to 10-digit Indian format
func NormalizePhone(phone string) string {
    var sb strings.Builder
    for _, r := range phone {
        if r >= '0' && r <= '9' {
            sb.WriteRune(r)
        }
    }
    s := sb.String()
    
    // Remove India country code if present
    if strings.HasPrefix(s, "91") && len(s) >= 12 {
        s = s[2:]
    }
    
    // Remove leading zeros
    for len(s) > 0 && s[0] == '0' {
        s = s[1:]
    }
    
    return s
}

// IsValidIndianPhone validates if a phone number is a valid 10-digit Indian mobile number
func IsValidIndianPhone(phone string) bool {
    normalized := NormalizePhone(phone)
    if len(normalized) != 10 {
        return false
    }
    return normalized[0] >= '6' && normalized[0] <= '9'
}