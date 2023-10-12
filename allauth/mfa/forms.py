from django import forms
from django.utils.translation import gettext_lazy as _

from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.parse_registration_credential_json import (
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from allauth.account.models import EmailAddress
from allauth.mfa import totp, webauthn
from allauth.mfa.adapter import get_adapter
from allauth.mfa.models import Authenticator


class AuthenticateForm(forms.Form):
    code = forms.CharField(label=_("Code"))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.request_options, self.expected_challenge = webauthn.get_request_challenge(
            user=self.user, regenerate=not self.is_bound
        )

    def clean_code(self):
        code = self.cleaned_data["code"]
        for auth in Authenticator.objects.filter(user=self.user):
            if auth.wrap().validate_code(code):
                self.authenticator = auth
                webauthn.delete_request_challenge()
                return code
        raise forms.ValidationError(get_adapter().error_messages["incorrect_code"])


class ActivateTOTPForm(forms.Form):
    code = forms.CharField(label=_("Authenticator code"))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        self.email_verified = not EmailAddress.objects.filter(
            user=self.user, verified=False
        ).exists()
        super().__init__(*args, **kwargs)
        self.secret = totp.get_totp_secret(regenerate=not self.is_bound)

    def clean_code(self):
        try:
            code = self.cleaned_data["code"]
            if not self.email_verified:
                raise forms.ValidationError(
                    get_adapter().error_messages["unverified_email"]
                )
            if not totp.validate_totp_code(self.secret, code):
                raise forms.ValidationError(
                    get_adapter().error_messages["incorrect_code"]
                )
            return code
        except forms.ValidationError as e:
            self.secret = totp.get_totp_secret(regenerate=True)
            raise e


class ActivateWebAuthnForm(forms.Form):
    token = forms.CharField(
        label=_("WebAuthn token"),
        widget=forms.HiddenInput(),
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        self.email_verified = not EmailAddress.objects.filter(
            user=self.user, verified=False
        ).exists()
        super().__init__(*args, **kwargs)

        excluded_credentials = Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.WEBAUTHN
        )
        excluded_credential_ids = [
            authenticator.data["id"] for authenticator in excluded_credentials
        ]

        self.options, self.expected_challenge = webauthn.get_creation_options(
            user=webauthn.get_user_entity(self.user),
            excluded_credential_ids=excluded_credential_ids,
            regenerate=not self.is_bound,
        )

    def clean_token(self):
        adapter = get_adapter()
        token = self.cleaned_data["token"]

        if not self.email_verified:
            raise forms.ValidationError(adapter.error_messages["unverified_email"])

        try:
            parse_registration_credential_json(token)
        except InvalidRegistrationResponse:
            raise forms.ValidationError(adapter.error_messages["incorrect_token"])

        webauthn.delete_creation_options()
        return token
