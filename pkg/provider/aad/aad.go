package aad

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

// Client wrapper around AzureAD enabling authentication and retrieval of assertions
type Client struct {
	provider.ValidateBase

	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// Autogenerate startSAML Response struct
// some case, some fields is not exists
type startSAMLResponse struct {
	FShowPersistentCookiesWarning         bool     `json:"fShowPersistentCookiesWarning"`
	URLMsaLogout                          string   `json:"urlMsaLogout"`
	ShowCantAccessAccountLink             bool     `json:"showCantAccessAccountLink"`
	URLGitHubFed                          string   `json:"urlGitHubFed"`
	FShowSignInWithGitHubOnlyOnCredPicker bool     `json:"fShowSignInWithGitHubOnlyOnCredPicker"`
	FEnableShowResendCode                 bool     `json:"fEnableShowResendCode"`
	IShowResendCodeDelay                  int      `json:"iShowResendCodeDelay"`
	SSMSCtryPhoneData                     string   `json:"sSMSCtryPhoneData"`
	FUseInlinePhoneNumber                 bool     `json:"fUseInlinePhoneNumber"`
	URLSessionState                       string   `json:"urlSessionState"`
	URLResetPassword                      string   `json:"urlResetPassword"`
	URLMsaResetPassword                   string   `json:"urlMsaResetPassword"`
	URLLogin                              string   `json:"urlLogin"`
	URLSignUp                             string   `json:"urlSignUp"`
	URLGetCredentialType                  string   `json:"urlGetCredentialType"`
	URLGetOneTimeCode                     string   `json:"urlGetOneTimeCode"`
	URLLogout                             string   `json:"urlLogout"`
	URLForget                             string   `json:"urlForget"`
	URLDisambigRename                     string   `json:"urlDisambigRename"`
	URLGoToAADError                       string   `json:"urlGoToAADError"`
	URLDssoStatus                         string   `json:"urlDssoStatus"`
	URLFidoHelp                           string   `json:"urlFidoHelp"`
	URLFidoLogin                          string   `json:"urlFidoLogin"`
	URLPostAad                            string   `json:"urlPostAad"`
	URLPostMsa                            string   `json:"urlPostMsa"`
	URLPIAEndAuth                         string   `json:"urlPIAEndAuth"`
	FCBShowSignUp                         bool     `json:"fCBShowSignUp"`
	FKMSIEnabled                          bool     `json:"fKMSIEnabled"`
	ILoginMode                            int      `json:"iLoginMode"`
	FAllowPhoneSignIn                     bool     `json:"fAllowPhoneSignIn"`
	FAllowPhoneInput                      bool     `json:"fAllowPhoneInput"`
	FAllowSkypeNameLogin                  bool     `json:"fAllowSkypeNameLogin"`
	IMaxPollErrors                        int      `json:"iMaxPollErrors"`
	IPollingTimeout                       int      `json:"iPollingTimeout"`
	SrsSuccess                            bool     `json:"srsSuccess"`
	FShowSwitchUser                       bool     `json:"fShowSwitchUser"`
	ArrValErrs                            []string `json:"arrValErrs"`
	SErrorCode                            string   `json:"sErrorCode"`
	SErrTxt                               string   `json:"sErrTxt"`
	SResetPasswordPrefillParam            string   `json:"sResetPasswordPrefillParam"`
	OnPremPasswordValidationConfig        struct {
		IsUserRealmPrecheckEnabled bool `json:"isUserRealmPrecheckEnabled"`
	} `json:"onPremPasswordValidationConfig"`
	FSwitchDisambig   bool `json:"fSwitchDisambig"`
	OCancelPostParams struct {
		Error        string `json:"error"`
		ErrorSubcode string `json:"error_subcode"`
		State        string `json:"state"`
	} `json:"oCancelPostParams"`
	IAllowedIdentities                  int         `json:"iAllowedIdentities"`
	IRemoteNgcPollingType               int         `json:"iRemoteNgcPollingType"`
	IsGlobalTenant                      bool        `json:"isGlobalTenant"`
	FIsFidoSupported                    bool        `json:"fIsFidoSupported"`
	FUseNewNoPasswordTypes              bool        `json:"fUseNewNoPasswordTypes"`
	IMaxStackForKnockoutAsyncComponents int         `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string      `json:"strCopyrightTxt"`
	FShowButtons                        bool        `json:"fShowButtons"`
	URLCdn                              string      `json:"urlCdn"`
	URLFooterTOU                        string      `json:"urlFooterTOU"`
	URLFooterPrivacy                    string      `json:"urlFooterPrivacy"`
	URLPost                             string      `json:"urlPost"`
	URLRefresh                          string      `json:"urlRefresh"`
	URLCancel                           string      `json:"urlCancel"`
	IPawnIcon                           int         `json:"iPawnIcon"`
	IPollingInterval                    int         `json:"iPollingInterval"`
	SPOSTUsername                       string      `json:"sPOST_Username"`
	SFT                                 string      `json:"sFT"`
	SFTName                             string      `json:"sFTName"`
	SSessionIdentifierName              string      `json:"sSessionIdentifierName"`
	SCtx                                string      `json:"sCtx"`
	IProductIcon                        int         `json:"iProductIcon"`
	URLReportPageLoad                   string      `json:"urlReportPageLoad"`
	StaticTenantBranding                interface{} `json:"staticTenantBranding"`
	OAppCobranding                      struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int           `json:"iBackgroundImage"`
	ArrSessions                           []interface{} `json:"arrSessions"`
	FUseConstantPolling                   bool          `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool          `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool          `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int           `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string        `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool          `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool          `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool          `json:"fIsRemoteNGCSupported"`
	Scid                                  int           `json:"scid"`
	Hpgact                                int           `json:"hpgact"`
	Hpgid                                 int           `json:"hpgid"`
	Pgid                                  string        `json:"pgid"`
	APICanary                             string        `json:"apiCanary"`
	Canary                                string        `json:"canary"`
	CorrelationID                         string        `json:"correlationId"`
	SessionID                             string        `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	Bsso                       struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"bsso"`
	URLNoCookies       string `json:"urlNoCookies"`
	FTrimChromeBssoURL bool   `json:"fTrimChromeBssoUrl"`
}

// Autogenerate GetCredentialType request
// some case, some fields is not exists
type GetCredentialTypeRequest struct {
	Username                       string `json:"username"`
	IsOtherIdpSupported            bool   `json:"isOtherIdpSupported"`
	CheckPhones                    bool   `json:"checkPhones"`
	IsRemoteNGCSupported           bool   `json:"isRemoteNGCSupported"`
	IsCookieBannerShown            bool   `json:"isCookieBannerShown"`
	IsFidoSupported                bool   `json:"isFidoSupported"`
	OriginalRequest                string `json:"originalRequest"`
	Country                        string `json:"country"`
	Forceotclogin                  bool   `json:"forceotclogin"`
	IsExternalFederationDisallowed bool   `json:"isExternalFederationDisallowed"`
	IsRemoteConnectSupported       bool   `json:"isRemoteConnectSupported"`
	FederationFlags                int    `json:"federationFlags"`
	IsSignup                       bool   `json:"isSignup"`
	FlowToken                      string `json:"flowToken"`
	IsAccessPassSupported          bool   `json:"isAccessPassSupported"`
}

// Autogenerate GetCredentialType response
// some case, some fields is not exists
type GetCredentialTypeResponse struct {
	Username       string `json:"Username"`
	Display        string `json:"Display"`
	IfExistsResult int    `json:"IfExistsResult"`
	IsUnmanaged    bool   `json:"IsUnmanaged"`
	ThrottleStatus int    `json:"ThrottleStatus"`
	Credentials    struct {
		PrefCredential        int         `json:"PrefCredential"`
		HasPassword           bool        `json:"HasPassword"`
		RemoteNgcParams       interface{} `json:"RemoteNgcParams"`
		FidoParams            interface{} `json:"FidoParams"`
		SasParams             interface{} `json:"SasParams"`
		CertAuthParams        interface{} `json:"CertAuthParams"`
		GoogleParams          interface{} `json:"GoogleParams"`
		FacebookParams        interface{} `json:"FacebookParams"`
		FederationRedirectURL string      `json:"FederationRedirectUrl"`
	} `json:"Credentials"`
	FlowToken          string `json:"FlowToken"`
	IsSignupDisallowed bool   `json:"IsSignupDisallowed"`
	APICanary          string `json:"apiCanary"`
}

// Autogenerate Authentication response
// some case, some fields is not exists
type AuthenticationResponse struct {
	IMaxStackForKnockoutAsyncComponents int    `json:"iMaxStackForKnockoutAsyncComponents"`
	FShowButtons                        bool   `json:"fShowButtons"`
	URLCdn                              string `json:"urlCdn"`
	URLDefaultFavicon                   string `json:"urlDefaultFavicon"`
	URLFooterTOU                        string `json:"urlFooterTOU"`
	URLFooterPrivacy                    string `json:"urlFooterPrivacy"`
	URLPost                             string `json:"urlPost"`
	IPawnIcon                           int    `json:"iPawnIcon"`
	SPOSTUsername                       string `json:"sPOST_Username"`
	SFT                                 string `json:"sFT"`
	SFTName                             string `json:"sFTName"`
	SCtx                                string `json:"sCtx"`
	SCanaryTokenName                    string `json:"sCanaryTokenName"`
	FIsRemoteNGCSupported               bool   `json:"fIsRemoteNGCSupported"`
	FUseSameSite                        bool   `json:"fUseSameSite"`
	IsGlobalTenant                      bool   `json:"isGlobalTenant"`
	FOfflineAccountVisible              bool   `json:"fOfflineAccountVisible"`
	ScriptNonce                         string `json:"scriptNonce"`
	FEnableUserStateFix                 bool   `json:"fEnableUserStateFix"`
	FShowAccessPassPeek                 bool   `json:"fShowAccessPassPeek"`
	FUpdateSessionPollingLogic          bool   `json:"fUpdateSessionPollingLogic"`
	Scid                                int    `json:"scid"`
	Hpgact                              int    `json:"hpgact"`
	Hpgid                               int    `json:"hpgid"`
	Pgid                                string `json:"pgid"`
	APICanary                           string `json:"apiCanary"`
	Canary                              string `json:"canary"`
	CorrelationID                       string `json:"correlationId"`
	SessionID                           string `json:"sessionId"`
	SlMaxRetry                          int    `json:"slMaxRetry"`
	SlReportFailure                     bool   `json:"slReportFailure"`
	Country                             string `json:"country"`
	URLNoCookies                        string `json:"urlNoCookies"`
	FTrimChromeBssoURL                  bool   `json:"fTrimChromeBssoUrl"`
	InlineMode                          int    `json:"inlineMode"`
}

// Autogenerate password login response
// some case, some fields is not exists
type passwordLoginResponse struct {
	ArrUserProofs                       []userProof        `json:"arrUserProofs"`
	FHideIHaveCodeLink                  bool               `json:"fHideIHaveCodeLink"`
	OPerAuthPollingInterval             map[string]float64 `json:"oPerAuthPollingInterval"`
	FProofIndexedByType                 bool               `json:"fProofIndexedByType"`
	URLBeginAuth                        string             `json:"urlBeginAuth"`
	URLEndAuth                          string             `json:"urlEndAuth"`
	ISAMode                             int                `json:"iSAMode"`
	ITrustedDeviceCheckboxConfig        int                `json:"iTrustedDeviceCheckboxConfig"`
	IMaxPollAttempts                    int                `json:"iMaxPollAttempts"`
	IPollingTimeout                     int                `json:"iPollingTimeout"`
	IPollingBackoffInterval             float64            `json:"iPollingBackoffInterval"`
	IRememberMfaDuration                float64            `json:"iRememberMfaDuration"`
	STrustedDeviceCheckboxName          string             `json:"sTrustedDeviceCheckboxName"`
	SAuthMethodInputFieldName           string             `json:"sAuthMethodInputFieldName"`
	ISAOtcLength                        int                `json:"iSAOtcLength"`
	ITotpOtcLength                      int                `json:"iTotpOtcLength"`
	URLMoreInfo                         string             `json:"urlMoreInfo"`
	FShowViewDetailsLink                bool               `json:"fShowViewDetailsLink"`
	FAlwaysUpdateFTInSasEnd             bool               `json:"fAlwaysUpdateFTInSasEnd"`
	IMaxStackForKnockoutAsyncComponents int                `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string             `json:"strCopyrightTxt"`
	FShowButtons                        bool               `json:"fShowButtons"`
	URLCdn                              string             `json:"urlCdn"`
	URLFooterTOU                        string             `json:"urlFooterTOU"`
	URLFooterPrivacy                    string             `json:"urlFooterPrivacy"`
	URLPost                             string             `json:"urlPost"`
	URLCancel                           string             `json:"urlCancel"`
	IPawnIcon                           int                `json:"iPawnIcon"`
	IPollingInterval                    int                `json:"iPollingInterval"`
	SPOSTUsername                       string             `json:"sPOST_Username"`
	SFT                                 string             `json:"sFT"`
	SFTName                             string             `json:"sFTName"`
	SCtx                                string             `json:"sCtx"`
	DynamicTenantBranding               []struct {
		Locale                 int    `json:"Locale"`
		Illustration           string `json:"Illustration"`
		UserIDLabel            string `json:"UserIdLabel"`
		KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
		UseTransparentLightBox bool   `json:"UseTransparentLightBox"`
	} `json:"dynamicTenantBranding"`
	OAppCobranding struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int    `json:"iBackgroundImage"`
	FUseConstantPolling                   bool   `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool   `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool   `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int    `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool   `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool   `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool   `json:"fIsRemoteNGCSupported"`
	Scid                                  int    `json:"scid"`
	Hpgact                                int    `json:"hpgact"`
	Hpgid                                 int    `json:"hpgid"`
	Pgid                                  string `json:"pgid"`
	APICanary                             string `json:"apiCanary"`
	Canary                                string `json:"canary"`
	CorrelationID                         string `json:"correlationId"`
	SessionID                             string `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	URLNoCookies               string `json:"urlNoCookies"`
	FTrimChromeBssoURL         bool   `json:"fTrimChromeBssoUrl"`
}

// Autogenerated skip mfa login response
type SkipMfaResponse struct {
	URLPostRedirect                     string `json:"urlPostRedirect"`
	URLSkipMfaRegistration              string `json:"urlSkipMfaRegistration"`
	URLMoreInfo                         string `json:"urlMoreInfo"`
	SProofUpToken                       string `json:"sProofUpToken"`
	SProofUpTokenName                   string `json:"sProofUpTokenName"`
	SProofUpAuthState                   string `json:"sProofUpAuthState"`
	SCanaryToken                        string `json:"sCanaryToken"`
	IRemainingDaysToSkipMfaRegistration int    `json:"iRemainingDaysToSkipMfaRegistration"`
	IMaxStackForKnockoutAsyncComponents int    `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string `json:"strCopyrightTxt"`
	FShowButtons                        bool   `json:"fShowButtons"`
	URLCdn                              string `json:"urlCdn"`
	URLFooterTOU                        string `json:"urlFooterTOU"`
	URLFooterPrivacy                    string `json:"urlFooterPrivacy"`
	URLPost                             string `json:"urlPost"`
	URLCancel                           string `json:"urlCancel"`
	IPawnIcon                           int    `json:"iPawnIcon"`
	SPOSTUsername                       string `json:"sPOST_Username"`
	SFT                                 string `json:"sFT"`
	SFTName                             string `json:"sFTName"`
	SCanaryTokenName                    string `json:"sCanaryTokenName"`
	DynamicTenantBranding               []struct {
		Locale                 int    `json:"Locale"`
		Illustration           string `json:"Illustration"`
		UserIDLabel            string `json:"UserIdLabel"`
		KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
		UseTransparentLightBox bool   `json:"UseTransparentLightBox"`
	} `json:"dynamicTenantBranding"`
	OAppCobranding struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int    `json:"iBackgroundImage"`
	FUseConstantPolling                   bool   `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool   `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool   `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int    `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool   `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool   `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool   `json:"fIsRemoteNGCSupported"`
	Scid                                  int    `json:"scid"`
	Hpgact                                int    `json:"hpgact"`
	Hpgid                                 int    `json:"hpgid"`
	Pgid                                  string `json:"pgid"`
	APICanary                             string `json:"apiCanary"`
	Canary                                string `json:"canary"`
	CorrelationID                         string `json:"correlationId"`
	SessionID                             string `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	URLNoCookies               string `json:"urlNoCookies"`
	FTrimChromeBssoURL         bool   `json:"fTrimChromeBssoUrl"`
}

// mfa request
type mfaRequest struct {
	AuthMethodID       string `json:"AuthMethodId"`
	Method             string `json:"Method"`
	Ctx                string `json:"Ctx"`
	FlowToken          string `json:"FlowToken"`
	SessionID          string `json:"SessionId,omitempty"`
	AdditionalAuthData string `json:"AdditionalAuthData,omitempty"`
}

// mfa response
type mfaResponse struct {
	Success       bool        `json:"Success"`
	ResultValue   string      `json:"ResultValue"`
	Message       interface{} `json:"Message"`
	AuthMethodID  string      `json:"AuthMethodId"`
	ErrCode       int         `json:"ErrCode"`
	Retry         bool        `json:"Retry"`
	FlowToken     string      `json:"FlowToken"`
	Ctx           string      `json:"Ctx"`
	SessionID     string      `json:"SessionId"`
	CorrelationID string      `json:"CorrelationId"`
	Timestamp     time.Time   `json:"Timestamp"`
}

// Autogenerate ProcessAuth response
// some case, some fields is not exists
type processAuthResponse struct {
	IMaxStackForKnockoutAsyncComponents int    `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string `json:"strCopyrightTxt"`
	FShowButtons                        bool   `json:"fShowButtons"`
	URLCdn                              string `json:"urlCdn"`
	URLFooterTOU                        string `json:"urlFooterTOU"`
	URLFooterPrivacy                    string `json:"urlFooterPrivacy"`
	URLPost                             string `json:"urlPost"`
	IPawnIcon                           int    `json:"iPawnIcon"`
	SPOSTUsername                       string `json:"sPOST_Username"`
	SFT                                 string `json:"sFT"`
	SFTName                             string `json:"sFTName"`
	SCtx                                string `json:"sCtx"`
	SCanaryTokenName                    string `json:"sCanaryTokenName"`
	DynamicTenantBranding               []struct {
		Locale                 int    `json:"Locale"`
		Illustration           string `json:"Illustration"`
		UserIDLabel            string `json:"UserIdLabel"`
		KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
		UseTransparentLightBox bool   `json:"UseTransparentLightBox"`
	} `json:"dynamicTenantBranding"`
	OAppCobranding struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int    `json:"iBackgroundImage"`
	FUseConstantPolling                   bool   `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool   `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool   `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int    `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool   `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool   `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool   `json:"fIsRemoteNGCSupported"`
	Scid                                  int    `json:"scid"`
	Hpgact                                int    `json:"hpgact"`
	Hpgid                                 int    `json:"hpgid"`
	Pgid                                  string `json:"pgid"`
	APICanary                             string `json:"apiCanary"`
	Canary                                string `json:"canary"`
	CorrelationID                         string `json:"correlationId"`
	SessionID                             string `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	URLNoCookies               string `json:"urlNoCookies"`
	FTrimChromeBssoURL         bool   `json:"fTrimChromeBssoUrl"`
}

// A given method for a user to prove their indentity
type userProof struct {
	AuthMethodID string `json:"authMethodId"`
	Data         string `json:"data"`
	Display      string `json:"display"`
	IsDefault    bool   `json:"isDefault"`
}

// New create a new AzureAD client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate to AzureAD and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var samlAssertion string
	var res *http.Response

	// idpAccount.URL = https://account.activedirectory.windowsazure.com

	// startSAML
	startURL := fmt.Sprintf("%s/applications/redirecttofederatedapplication.aspx?Operation=LinkedSignIn&applicationId=%s", ac.idpAccount.URL, ac.idpAccount.AppID)

	startSAMLResp, res, err := ac.requestConvergedSignIn(startURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error processing ConvergedSignIn request")
	}

	loginRequestUrl := ac.fullUrl(res, startSAMLResp.URLPost)

	refererUrl := res.Request.URL.String()

	getCredentialTypeResponse, _, err := ac.requestGetCredentialType(refererUrl, loginDetails, startSAMLResp)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error processing GetCredentialType request")
	}

	federationRedirectURL := getCredentialTypeResponse.Credentials.FederationRedirectURL

	var authenticationResponse AuthenticationResponse
	if federationRedirectURL != "" {
		authenticationResponse, res, err = ac.processADFSAuthentication(federationRedirectURL, loginDetails)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error authenticating")
		}
	} else {
		authenticationResponse, res, err = ac.processAuthentication(loginRequestUrl, refererUrl, loginDetails, startSAMLResp)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error authenticating")
		}
	}

	res, err = ac.kmsiRequest(ac.fullUrl(res, authenticationResponse.URLPost), authenticationResponse.SFT, authenticationResponse.SCtx)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error processing KMSI request")
	}

	resBodyStr, _ := ac.responseBodyAsString(res.Body)

	if ac.isHiddenForm(resBodyStr) {
		resBodyStr, _, err = ac.reProcessForm(resBodyStr)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error processing hiddenform")
		}
	}

	// data is embedded javascript
	// window.location = 'https:/..../?SAMLRequest=......'
	oidcResponseList := strings.Split(resBodyStr, ";")
	var SAMLRequestURL string
	for _, v := range oidcResponseList {
		if strings.Contains(v, "SAMLRequest") {
			startURLPos := strings.Index(v, "https://")
			endURLPos := strings.Index(v[startURLPos:], "'")
			if endURLPos == -1 {
				endURLPos = strings.Index(v[startURLPos:], "\"")
			}
			SAMLRequestURL = v[startURLPos : startURLPos+endURLPos]
		}

	}
	if SAMLRequestURL == "" {
		return samlAssertion, fmt.Errorf("unable to locate SAMLRequest URL")
	}

	res, err = ac.client.Get(SAMLRequestURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving SAMLRequest results")
	}
	resBodyStr, _ = ac.responseBodyAsString(res.Body)

	if ac.isHiddenForm(resBodyStr) {
		resBodyStr, res, err = ac.reProcessForm(resBodyStr)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error processing hiddenform")
		}
	}

	if strings.Contains(resBodyStr, "arrUserProofs") {
		resBodyStr, err = ac.processAuth(resBodyStr, res)
		if err != nil {
			return samlAssertion, err
		}
	}

	// data in input tag
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(resBodyStr))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		attrName, ok := s.Attr("name")
		if !ok {
			return
		}
		if attrName != "SAMLResponse" {
			return
		}
		samlAssertion, _ = s.Attr("value")
	})
	if samlAssertion != "" {
		return samlAssertion, nil
	}
	res, err = ac.reProcess(resBodyStr)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to saml request reprocess")
	}
	resBodyStr, _ = ac.responseBodyAsString(res.Body)
	doc, err = goquery.NewDocumentFromReader(strings.NewReader(resBodyStr))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from result body")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		attrName, ok := s.Attr("name")
		if !ok {
			return
		}

		if attrName != "SAMLResponse" {
			return
		}

		samlAssertion, _ = s.Attr("value")
	})
	if samlAssertion != "" {
		return samlAssertion, nil
	}

	return samlAssertion, errors.New("failed get SAMLAssertion")
}

func (ac *Client) requestConvergedSignIn(url string) (startSAMLResponse, *http.Response, error) {
	var res *http.Response
	var err error
	var resBodyStr string
	var convergedSignInResponse startSAMLResponse

	res, err = ac.client.Get(url)
	if err != nil {
		return convergedSignInResponse, res, errors.Wrap(err, "error retrieving ConvergedSignIn form")
	}

	resBodyStr, _ = ac.responseBodyAsString(res.Body)

	if err := json.Unmarshal([]byte(ac.getJsonFromConfig(resBodyStr)), &convergedSignInResponse); err != nil {
		return convergedSignInResponse, res, errors.Wrap(err, "ConvergedSignIn response unmarshal error")
	}

	return convergedSignInResponse, res, nil
}

func (ac *Client) requestGetCredentialType(refererUrl string, loginDetails *creds.LoginDetails, convergedSignInResponse startSAMLResponse) (GetCredentialTypeResponse, *http.Response, error) {
	var res *http.Response
	var getCredentialTypeResponse GetCredentialTypeResponse

	reqBodyObj := GetCredentialTypeRequest{
		Username:             loginDetails.Username,
		IsOtherIdpSupported:  true,
		CheckPhones:          false,
		IsRemoteNGCSupported: false,
		IsCookieBannerShown:  false,
		IsFidoSupported:      false,
		OriginalRequest:      convergedSignInResponse.SCtx,
		FlowToken:            convergedSignInResponse.SFT,
	}
	reqBodyJson, err := json.Marshal(reqBodyObj)
	if err != nil {
		return getCredentialTypeResponse, res, errors.Wrap(err, "failed to build GetCredentialType request JSON")
	}

	req, err := http.NewRequest("POST", convergedSignInResponse.URLGetCredentialType, strings.NewReader(string(reqBodyJson)))
	if err != nil {
		return getCredentialTypeResponse, res, errors.Wrap(err, "error building GetCredentialType request")
	}

	req.Header.Add("canary", convergedSignInResponse.APICanary)
	req.Header.Add("client-request-id", convergedSignInResponse.CorrelationID)
	req.Header.Add("hpgact", fmt.Sprint(convergedSignInResponse.Hpgact))
	req.Header.Add("hpgid", fmt.Sprint(convergedSignInResponse.Hpgid))
	req.Header.Add("hpgrequestid", convergedSignInResponse.SessionID)
	req.Header.Add("Referer", refererUrl)

	res, err = ac.client.Do(req)
	if err != nil {
		return getCredentialTypeResponse, res, errors.Wrap(err, "error retrieving GetCredentialType results")
	}

	err = json.NewDecoder(res.Body).Decode(&getCredentialTypeResponse)
	if err != nil {
		return getCredentialTypeResponse, res, errors.Wrap(err, "error decoding GetCredentialType results")
	}

	return getCredentialTypeResponse, res, nil
}

func (ac *Client) processADFSAuthentication(federationUrl string, loginDetails *creds.LoginDetails) (AuthenticationResponse, *http.Response, error) {
	var res *http.Response
	var err error
	var resBodyStr string
	var authenticationResponse AuthenticationResponse
	var formValues url.Values
	var formSubmitUrl string
	var req *http.Request

	res, err = ac.client.Get(federationUrl)
	if err != nil {
		return authenticationResponse, res, errors.Wrap(err, "error retrieving ADFS url")
	}

	resBodyStr, _ = ac.responseBodyAsString(res.Body)

	formValues, formSubmitUrl, err = ac.reSubmitFormData(resBodyStr)
	if err != nil {
		return authenticationResponse, res, errors.Wrap(err, "failed to parse ADFS login form")
	}

	if formSubmitUrl == "" {
		return authenticationResponse, res, fmt.Errorf("unable to locate ADFS form submit URL")
	}

	formValues.Set("UserName", loginDetails.Username)
	formValues.Set("Password", loginDetails.Password)
	formValues.Set("AuthMethod", "FormsAuthentication")

	req, err = http.NewRequest("POST", ac.fullUrl(res, formSubmitUrl), strings.NewReader(formValues.Encode()))
	if err != nil {
		return authenticationResponse, res, errors.Wrap(err, "error building ADFS login request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = ac.client.Do(req)
	if err != nil {
		return authenticationResponse, res, errors.Wrap(err, "error retrieving ADFS login results")
	}

	resBodyStr, _ = ac.responseBodyAsString(res.Body)

	if ac.isHiddenForm(resBodyStr) {
		resBodyStr, res, err = ac.reProcessForm(resBodyStr)
		if err != nil {
			return authenticationResponse, res, errors.Wrap(err, "error processing hiddenform")
		}
	}

	if err := json.Unmarshal([]byte(ac.getJsonFromConfig(resBodyStr)), &authenticationResponse); err != nil {
		return authenticationResponse, res, errors.Wrap(err, "ADFS login response unmarshal error")
	}

	return authenticationResponse, res, nil
}

func (ac *Client) processAuthentication(loginUrl string, refererUrl string, loginDetails *creds.LoginDetails, convergedSignInResponse startSAMLResponse) (AuthenticationResponse, *http.Response, error) {
	var res *http.Response
	var err error
	var resBodyStr string
	var authenticationResponse AuthenticationResponse
	var req *http.Request

	formValues := url.Values{}
	formValues.Set("canary", convergedSignInResponse.Canary)
	formValues.Set("hpgrequestid", convergedSignInResponse.SessionID)
	formValues.Set(convergedSignInResponse.SFTName, convergedSignInResponse.SFT)
	formValues.Set("ctx", convergedSignInResponse.SCtx)
	formValues.Set("login", loginDetails.Username)
	formValues.Set("loginfmt", loginDetails.Username)
	formValues.Set("passwd", loginDetails.Password)

	req, err = http.NewRequest("POST", loginUrl, strings.NewReader(formValues.Encode()))
	if err != nil {
		return authenticationResponse, res, errors.Wrap(err, "error building login request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", refererUrl)

	res, err = ac.client.Do(req)
	if err != nil {
		return authenticationResponse, res, errors.Wrap(err, "error retrieving login results")
	}

	resBodyStr, _ = ac.responseBodyAsString(res.Body)

	if err := json.Unmarshal([]byte(ac.getJsonFromConfig(resBodyStr)), &authenticationResponse); err != nil {
		return authenticationResponse, res, errors.Wrap(err, "login response unmarshal error")
	}

	// any authentication problem leads back to the origin ConvergedSignIn page
	if authenticationResponse.Pgid == "ConvergedSignIn" {
		var convergedSignInResponse startSAMLResponse
		if err := json.Unmarshal([]byte(ac.getJsonFromConfig(resBodyStr)), &convergedSignInResponse); err != nil {
			return authenticationResponse, res, errors.Wrap(err, "login response unmarshal error")
		}
		return authenticationResponse, res, fmt.Errorf("login error " + convergedSignInResponse.SErrorCode)
	}

	return authenticationResponse, res, nil
}

func (ac *Client) reProcess(resBodyStr string) (*http.Response, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(resBodyStr))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	var action, ctx, flowToken string
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ = s.Attr("action")
	})
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		attrName, ok := s.Attr("name")
		if !ok {
			return
		}
		if attrName == "ctx" {
			ctx, _ = s.Attr("value")
		}
		if attrName == "flowtoken" {
			flowToken, _ = s.Attr("value")
		}
	})

	reprocessValues := url.Values{}
	reprocessValues.Set("ctx", ctx)
	reprocessValues.Set("flowtoken", flowToken)
	reprocessRequest, err := http.NewRequest("post", action, strings.NewReader(reprocessValues.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error reprocess create httpRequest")
	}
	reprocessRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := ac.client.Do(reprocessRequest)
	if err != nil {
		return res, errors.Wrap(err, "error reprocess results")
	}
	return res, nil
}

func (ac *Client) buildMfaRequestJson(mfas []userProof, flowToken string, ctx string) ([]byte, error) {
	mfa := mfas[0]
	switch ac.idpAccount.MFA {

	case "Auto":
		for _, v := range mfas {
			if v.IsDefault {
				mfa = v
				break
			}
		}
	default:
		for _, v := range mfas {
			if v.AuthMethodID == ac.idpAccount.MFA {
				mfa = v
				break
			}
		}
	}
	mfaReq := mfaRequest{AuthMethodID: mfa.AuthMethodID, Method: "BeginAuth", Ctx: ctx, FlowToken: flowToken}
	return json.Marshal(mfaReq)
}

func (ac *Client) getJsonFromConfig(resBodyStr string) string {
	/*
	 * data is embedded in a javascript object
	 * <script><![CDATA[  $Config=......; ]]>
	 */
	startIndex := strings.Index(resBodyStr, "$Config=") + 8
	endIndex := startIndex + strings.Index(resBodyStr[startIndex:], ";")
	return resBodyStr[startIndex:endIndex]
}

func (ac *Client) getMfaFlowToken(mfas []userProof, loginPasswordResp passwordLoginResponse) (mfaResponse, error) {
	var mfaResp mfaResponse
	if len(mfas) == 0 {
		return mfaResp, fmt.Errorf("mfa not found")
	}
	mfaReqJson, err := ac.buildMfaRequestJson(mfas, loginPasswordResp.SFT, loginPasswordResp.SCtx)
	if err != nil {
		return mfaResp, err
	}
	mfaBeginRequest, err := http.NewRequest("POST", loginPasswordResp.URLBeginAuth, strings.NewReader(string(mfaReqJson)))
	if err != nil {
		return mfaResp, errors.Wrap(err, "error retrieving begin mfa")
	}
	mfaBeginRequest.Header.Add("Content-Type", "application/json")
	res, err := ac.client.Do(mfaBeginRequest)
	if err != nil {
		return mfaResp, errors.Wrap(err, "error retrieving begin mfa")
	}
	mfaBeginJson := make([]byte, res.ContentLength)
	if n, err := res.Body.Read(mfaBeginJson); err != nil && err != io.EOF || n != int(res.ContentLength) {
		return mfaResp, errors.Wrap(err, "mfa BeginAuth response error")
	}

	if err := json.Unmarshal(mfaBeginJson, &mfaResp); err != nil {
		return mfaResp, errors.Wrap(err, "mfa BeginAuth  response unmarshal error")
	}
	if !mfaResp.Success {
		return mfaResp, fmt.Errorf("mfa BeginAuth is not success %v", mfaResp.Message)
	}

	//  mfa end
	for i := 0; ; i++ {
		mfaReq := mfaRequest{
			AuthMethodID: mfaResp.AuthMethodID,
			Method:       "EndAuth",
			Ctx:          mfaResp.Ctx,
			FlowToken:    mfaResp.FlowToken,
			SessionID:    mfaResp.SessionID,
		}
		if mfaReq.AuthMethodID == "PhoneAppOTP" || mfaReq.AuthMethodID == "OneWaySMS" {
			verifyCode := prompter.StringRequired("Enter verification code")
			mfaReq.AdditionalAuthData = verifyCode
		}
		if mfaReq.AuthMethodID == "PhoneAppNotification" && i == 0 {
			log.Println("Phone approval required.")
		}
		mfaReqJson, err := json.Marshal(mfaReq)
		if err != nil {
			return mfaResp, err
		}
		mfaEndRequest, err := http.NewRequest("POST", loginPasswordResp.URLEndAuth, strings.NewReader(string(mfaReqJson)))
		if err != nil {
			return mfaResp, errors.Wrap(err, "error retrieving begin mfa")
		}
		mfaEndRequest.Header.Add("Content-Type", "application/json")
		res, err = ac.client.Do(mfaEndRequest)
		if err != nil {
			return mfaResp, errors.Wrap(err, "error retrieving begin mfa")
		}
		mfaJson := make([]byte, res.ContentLength)
		if n, err := res.Body.Read(mfaJson); err != nil && err != io.EOF || n != int(res.ContentLength) {
			return mfaResp, errors.Wrap(err, "mfa EndAuth response error")
		}
		if err := json.Unmarshal(mfaJson, &mfaResp); err != nil {
			return mfaResp, errors.Wrap(err, "mfa EndAuth  response unmarshal error")
		}
		if mfaResp.ErrCode != 0 {
			return mfaResp, fmt.Errorf("error mfa fail errcode: %d, message: %v", mfaResp.ErrCode, mfaResp.Message)
		}
		if mfaResp.Success {
			break
		}
		if !mfaResp.Retry {
			break
		}
		// if mfaResp.Retry == true then
		// must exist loginPasswordResp.OPerAuthPollingInterval[mfaResp.AuthMethodID]
		time.Sleep(time.Duration(loginPasswordResp.OPerAuthPollingInterval[mfaResp.AuthMethodID]) * time.Second)
	}
	if !mfaResp.Success {
		return mfaResp, fmt.Errorf("error mfa fail")
	}
	return mfaResp, nil
}

func (ac *Client) kmsiRequest(requestUrl string, flowToken string, ctx string) (*http.Response, error) {
	var res *http.Response

	formValues := url.Values{}
	formValues.Set("flowToken", flowToken)
	formValues.Set("ctx", ctx)
	formValues.Set("LoginOptions", "1")

	req, err := http.NewRequest("POST", requestUrl, strings.NewReader(formValues.Encode()))
	if err != nil {
		return res, errors.Wrap(err, "error building KMSI request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	ac.client.DisableFollowRedirect()
	res, err = ac.client.Do(req)
	if err != nil {
		return res, errors.Wrap(err, "error retrieving KMSI results")
	}
	ac.client.EnableFollowRedirect()

	return res, nil
}

func (ac *Client) processAuth(srcBodyStr string, res *http.Response) (string, error) {
	var err error
	var loginPasswordResp passwordLoginResponse
	var loginPasswordSkipMfaResp SkipMfaResponse
	var restartSAMLResp startSAMLResponse
	var resBodyStr string

	loginPasswordJson := ac.getJsonFromConfig(srcBodyStr)

	if err := json.Unmarshal([]byte(loginPasswordJson), &loginPasswordResp); err != nil {
		return resBodyStr, errors.Wrap(err, "loginPassword response unmarshal error")
	}
	if err := json.Unmarshal([]byte(loginPasswordJson), &loginPasswordSkipMfaResp); err != nil {
		return resBodyStr, errors.Wrap(err, "loginPassword response unmarshal error")
	}
	if err := json.Unmarshal([]byte(loginPasswordJson), &restartSAMLResp); err != nil {
		return resBodyStr, errors.Wrap(err, "startSAML response unmarshal error")
	}

	mfas := loginPasswordResp.ArrUserProofs

	// If there's an explicit option to skip MFA, do so
	if loginPasswordSkipMfaResp.URLSkipMfaRegistration != "" {
		res, err = ac.client.Get(loginPasswordSkipMfaResp.URLSkipMfaRegistration)
		if err != nil {
			return resBodyStr, errors.Wrap(err, "error retrieving skip mfa results")
		}
	} else if len(mfas) != 0 {
		// There's no explicit option to skip MFA, and MFA options are available
		// Start MFA
		mfaResp, err := ac.getMfaFlowToken(mfas, loginPasswordResp)
		if err != nil {
			return resBodyStr, err
		}

		// ProcessAuth
		res, err = ac.processMfaAuth(mfaResp, loginPasswordResp, restartSAMLResp)
		if err != nil {
			return resBodyStr, err
		}
	}
	// There was no explicit link to skip MFA
	// and there were no MFA options available for us to process
	// This can happen if MFA is enabled, but we're accessing from a MFA trusted IP
	// See https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-mfasettings#targetText=MFA%20service%20settings,-Settings%20for%20app&targetText=Service%20settings%20can%20be%20accessed,Additional%20cloud-based%20MFA%20settings.
	// Proceed with login as normal

	// If we've been prompted with KMSI despite not going via MFA flow
	// Azure can do this if MFA is enabled but
	//  - we're accessing from an MFA whitelisted / trusted IP
	//  - we've been exempted from a Conditional Access Policy
	if loginPasswordResp.URLPost == "/kmsi" {
		res, err = ac.kmsiRequest(ac.fullUrl(res, loginPasswordResp.URLPost), loginPasswordResp.SFT, loginPasswordResp.SCtx)
		if err != nil {
			return resBodyStr, err
		}
	}

	return ac.responseBodyAsString(res.Body)
}

func (ac *Client) processMfaAuth(mfaResp mfaResponse, loginPasswordResp passwordLoginResponse, restartSAMLResp startSAMLResponse) (*http.Response, error) {
	var res *http.Response
	ProcessAuthValues := url.Values{}
	ProcessAuthValues.Set(restartSAMLResp.SFTName, mfaResp.FlowToken)
	ProcessAuthValues.Set("request", mfaResp.Ctx)
	ProcessAuthValues.Set("login", loginPasswordResp.SPOSTUsername)

	ProcessAuthRequest, err := http.NewRequest("POST", loginPasswordResp.URLPost, strings.NewReader(ProcessAuthValues.Encode()))
	if err != nil {
		return res, errors.Wrap(err, "error retrieving process auth results")
	}
	ProcessAuthRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = ac.client.Do(ProcessAuthRequest)
	if err != nil {
		return res, errors.Wrap(err, "error retrieving process auth results")
	}
	// data is embeded javascript object
	// <script><![CDATA[  $Config=......; ]]>
	resBody, _ := ioutil.ReadAll(res.Body)
	resBodyStr := string(resBody)
	// reset res.Body so it can be read again later if required
	res.Body = ioutil.NopCloser(bytes.NewBuffer(resBody))

	// After performing MFA we may be prompted with KMSI (Keep Me Signed In) page
	// Ref: https://docs.microsoft.com/ja-jp/azure/active-directory/fundamentals/keep-me-signed-in
	if strings.Contains(resBodyStr, "$Config") {
		ProcessAuthJson := ac.getJsonFromConfig(resBodyStr)

		var processAuthResp processAuthResponse
		if err := json.Unmarshal([]byte(ProcessAuthJson), &processAuthResp); err != nil {
			return res, errors.Wrap(err, "ProcessAuth response unmarshal error")
		}

		res, err = ac.kmsiRequest(ac.fullUrl(res, processAuthResp.URLPost), processAuthResp.SFT, processAuthResp.SCtx)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func (ac *Client) responseBodyAsString(body io.ReadCloser) (string, error) {
	resBody, err := ioutil.ReadAll(body)
	return string(resBody), err
}

func (ac *Client) fullUrl(res *http.Response, urlFragment string) string {
	if strings.HasPrefix(urlFragment, "/") {
		return res.Request.URL.Scheme + "://" + res.Request.URL.Host + urlFragment
	} else {
		return urlFragment
	}
}

func (ac *Client) isHiddenForm(resBodyStr string) bool {
	return strings.HasPrefix(resBodyStr, "<html><head><title>Working...</title>") && strings.Contains(resBodyStr, "name=\"hiddenform\"")
}

func (ac *Client) reProcessForm(srcBodyStr string) (string, *http.Response, error) {
	var res *http.Response
	var err error
	var resBodyStr string
	var formValues url.Values
	var formSubmitUrl string

	formValues, formSubmitUrl, err = ac.reSubmitFormData(srcBodyStr)
	if err != nil {
		return resBodyStr, res, errors.Wrap(err, "failed to parse hiddenform form")
	}

	if formSubmitUrl == "" {
		return resBodyStr, res, fmt.Errorf("unable to locate hiddenform submit URL")
	}

	req, err := http.NewRequest("POST", formSubmitUrl, strings.NewReader(formValues.Encode()))
	if err != nil {
		return resBodyStr, res, errors.Wrap(err, "error building hiddenform request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = ac.client.Do(req)
	if err != nil {
		return resBodyStr, res, errors.Wrap(err, "error retrieving hiddenform results")
	}

	resBodyStr, _ = ac.responseBodyAsString(res.Body)

	return resBodyStr, res, nil
}

func (ac *Client) reSubmitFormData(resBodyStr string) (url.Values, string, error) {
	formValues := url.Values{}
	var formSubmitUrl string

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(resBodyStr))
	if err != nil {
		return formValues, formSubmitUrl, errors.Wrap(err, "failed to build document from response")
	}

	// prefil form data from page as provided
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		value, ok := s.Attr("value")
		if !ok {
			return
		}
		formValues.Set(name, value)
	})

	// identify form submit url/path
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		formSubmitUrl = action
	})

	return formValues, formSubmitUrl, nil
}
