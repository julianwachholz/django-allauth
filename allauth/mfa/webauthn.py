from hashlib import sha1

from pydantic import ValidationError
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

from allauth.core import context
from allauth.mfa.adapter import get_adapter
from allauth.mfa.models import Authenticator


CREATION_OPTIONS_SESSION_KEY = "mfa.webauthn.creation_options"
REQUEST_OPTIONS_SESSION_KEY = "mfa.webauthn.request_options"


def get_user_entity(user):
    return PublicKeyCredentialUserEntity(
        id=sha1(str(user.pk).encode("utf-8")).hexdigest().encode("utf-8"),
        name=user.get_username(),
        display_name=user.get_full_name() or user.get_username(),
    )


def get_creation_options(
    user: PublicKeyCredentialUserEntity,
    excluded_credential_ids: list[str] = None,
    regenerate=False,
) -> tuple[str, str]:
    """
    :returns: A tuple of (creation_options_json, expected_challenge)
    """
    options = None
    if not regenerate:
        options = context.request.session.get(CREATION_OPTIONS_SESSION_KEY)
    if not options:
        options = context.request.session[
            CREATION_OPTIONS_SESSION_KEY
        ] = generate_creation_options(user, excluded_credential_ids)
    return options


def generate_creation_options(
    user: PublicKeyCredentialUserEntity, excluded_credential_ids=None, challenge=None
):
    adapter = get_adapter()
    rp = PublicKeyCredentialRpEntity(
        id=adapter.get_webauthn_rp_id(),
        name=adapter.get_webauthn_rp_name(),
    )

    if excluded_credential_ids is None:
        excluded_credential_ids = []
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))
        for credential_id in excluded_credential_ids
    ]

    if challenge:
        challenge = base64url_to_bytes(challenge)

    authenticator_attachment = None
    # if app_settings.MFA_AUTHENTICATOR_ATTACHMENT:
    #     authenticator_attachment = AuthenticatorAttachment(
    #         app_settings.MFA_AUTHENTICATOR_ATTACHMENT
    #     )

    creation_options = generate_registration_options(
        rp_id=rp.id,
        rp_name=rp.name,
        user_id=user.id.decode("utf-8"),
        user_name=user.name,
        user_display_name=user.display_name,
        challenge=challenge,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=authenticator_attachment,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        ),
        exclude_credentials=exclude_credentials,
    )
    return options_to_json(creation_options), bytes_to_base64url(
        creation_options.challenge
    )


def delete_creation_options():
    if CREATION_OPTIONS_SESSION_KEY in context.request.session:
        del context.request.session[CREATION_OPTIONS_SESSION_KEY]


def get_request_challenge(user, regenerate=False) -> tuple[str, str]:
    """
    :returns: A tuple of (request_options_json, request_challenge)
    """
    print(f"get_request_challenge({regenerate=})")
    options = None
    if not regenerate:
        options = context.request.session.get(REQUEST_OPTIONS_SESSION_KEY)
    if not options:
        options = context.request.session[
            REQUEST_OPTIONS_SESSION_KEY
        ] = generate_request_challenge(user)
    print(f"request challenge options = {options[0]}")
    return options


def generate_request_challenge(user):
    authenticators = Authenticator.objects.filter(
        user=user, type=Authenticator.Type.WEBAUTHN
    )
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(authenticator.data["id"]))
        for authenticator in authenticators
    ]

    request_options = generate_authentication_options(
        rp_id=get_adapter().get_webauthn_rp_id(),
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    return (
        options_to_json(request_options),
        bytes_to_base64url(request_options.challenge),
    )


def delete_request_challenge():
    del context.request.session[REQUEST_OPTIONS_SESSION_KEY]


class WebAuthn:
    def __init__(self, instance):
        self.instance = instance

    @classmethod
    def activate(cls, user, expected_challenge, token):
        adapter = get_adapter()
        verified_registration = verify_registration_response(
            credential=token,
            expected_challenge=base64url_to_bytes(expected_challenge),
            expected_origin=adapter.get_webauthn_origin(),
            expected_rp_id=adapter.get_webauthn_rp_id(),
        )
        instance = Authenticator(
            user=user,
            type=Authenticator.Type.WEBAUTHN,
            data={
                "id": bytes_to_base64url(verified_registration.credential_id),
                "public_key": bytes_to_base64url(
                    verified_registration.credential_public_key
                ),
                "sign_count": verified_registration.sign_count,
            },
        )
        instance.save()
        return cls(instance)

    def deactivate(self):
        self.instance.delete()
        Authenticator.objects.delete_dangling_recovery_codes(self.instance.user)

    def validate_code(self, code):
        _request_options, expected_challenge = get_request_challenge(
            user=self.instance.user
        )
        adapter = get_adapter()

        try:
            credential_id = parse_authentication_credential_json(code).id
            if self.instance.data["id"] != credential_id:
                return False
            verified_authentication = verify_authentication_response(
                credential=code,
                expected_challenge=base64url_to_bytes(expected_challenge),
                expected_rp_id=adapter.get_webauthn_rp_id(),
                expected_origin=adapter.get_webauthn_origin(),
                credential_public_key=base64url_to_bytes(
                    self.instance.data["public_key"]
                ),
                credential_current_sign_count=self.instance.data["sign_count"],
            )

            self.instance.data["sign_count"] = verified_authentication.new_sign_count
            self.instance.save()
            return True
        except (ValidationError, InvalidAuthenticationResponse) as e:
            print(f"ERROR: {e}")
            get_request_challenge(user=self.instance.user, regenerate=True)
        return False
