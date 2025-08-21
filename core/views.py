from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from core.models import Invite, PartnerLink, UserData
from core.serializers import (
    UserDataSerializer,
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    AcceptInvitationSerializer,
    GoogleLoginSerializer,
    LogoutSerializer
)
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, OpenApiResponse
from .utils import create_user_data_log

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


class InvitationAndAcceptViewset(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        description="Create an invitation code for a partner.",
        responses={
            201: OpenApiResponse(response={"invite_code": "string"}),
            400: OpenApiResponse(
                response={"error": "You must unlink before creating a new invite"}
            ),
        },
    )
    @action(methods=["GET"], detail=False, url_path="create-invitation")
    def create_invitation(self, request):
        # Check if user already has a partner linked
        if PartnerLink.objects.filter(user=request.user).exists():
            return Response(
                {"error": "You must unlink before creating a new invite"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        invite = Invite.objects.create(created_by=request.user)
        return Response(
            {"invite_code": str(invite.code)}, status=status.HTTP_201_CREATED
        )

    @extend_schema(
        request=AcceptInvitationSerializer,
        responses={200: OpenApiResponse(response={"message": "Linked successfully!"})},
    )
    @action(methods=["POST"], detail=False, url_path="accept-invitation")
    def accept_invitation(self, request):
        serializer = AcceptInvitationSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data["invite_code"]
        try:
            invite = Invite.objects.get(code=code, is_used=False)
        except Invite.DoesNotExist:
            return Response(
                {"error": "Invite not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Check if link already exists
        if PartnerLink.objects.filter(user=request.user).exists():
            return Response(
                {"error": "You already have a partner linked"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if PartnerLink.objects.filter(user=invite.created_by).exists():
            return Response(
                {"error": "This invite creator already has a partner"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        # 🚫 Prevent self-linking
        if invite.created_by == request.user:
            return Response(
                {"error": "You cannot accept your own invite code"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create mutual partner links
        PartnerLink.objects.create(user=request.user, partner=invite.created_by)
        PartnerLink.objects.create(user=invite.created_by, partner=request.user)

        invite.is_used = True
        invite.save()

        return Response({"message": "Linked successfully!"}, status=status.HTTP_200_OK)

    @extend_schema(
        description="Unlink the current user from their partner.",
        responses={
            200: OpenApiResponse(response={"message": "Unlinked successfully!"}),
            400: OpenApiResponse(response={"error": "No partner linked"}),
        },
    )
    @action(methods=["DELETE"], detail=False, url_path="unlink")
    def unlink_partner(self, request):
        try:
            # Get current link
            link = PartnerLink.objects.get(user=request.user)
            partner = link.partner

            # Delete both sides of the link
            PartnerLink.objects.filter(user=request.user).delete()
            PartnerLink.objects.filter(user=partner).delete()

            return Response(
                {"message": "Unlinked successfully!"}, status=status.HTTP_200_OK
            )

        except PartnerLink.DoesNotExist:
            return Response(
                {"error": "No partner linked"}, status=status.HTTP_400_BAD_REQUEST
            )


class UserDataViewset(viewsets.ViewSet):
    @extend_schema(
        request=UserDataSerializer,
        responses={201: UserDataSerializer},
    )
    @action(methods=["POST"], detail=False, url_path="update")
    def update_data(self, request):
        user_data, _ = UserData.objects.get_or_create(user=request.user)

        serializer = UserDataSerializer(user_data, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            # figure out which fields are updated
            field_map = {
                "battery": "Battery",
                "gps_lat": "GPS Latitude",
                "gps_lon": "GPS Longitude",
                "mood": "Mood",
            }
            updated_fields = [field for field in field_map.keys() if field in request.data]

            # build note string
            if len(updated_fields) == 1:
                note = f"{field_map[updated_fields[0]]} updated"
            else:
                note = ", ".join([field_map[f] for f in updated_fields]) + " updated"

            # prepare kwargs only for updated fields
            log_kwargs = {field: request.data.get(field) for field in updated_fields}
            log_kwargs["note"] = note

            # create log entry
            create_user_data_log(user_data=user_data, **log_kwargs)

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        responses={200: UserDataSerializer},
    )
    @extend_schema(
        responses={200: UserDataSerializer},
    )
    @action(methods=["GET"], detail=False, url_path="partner-data")
    def partner_data(self, request):
        try:
            partner = request.user.user_link.partner
        except PartnerLink.DoesNotExist:
            return Response(
                {"error": "No partner linked"}, status=status.HTTP_400_BAD_REQUEST
            )

        partner_data, _ = UserData.objects.get_or_create(user=partner)
        return Response(UserDataSerializer(partner_data).data)

    @extend_schema(
        responses={200: UserSerializer},
    )
    @action(methods=["GET"], detail=False, url_path="partner-info")
    def partner_info(self, request):
        try:
            partner = request.user.user_link.partner
        except PartnerLink.DoesNotExist:
            return Response(
                {"error": "No partner linked"}, status=status.HTTP_400_BAD_REQUEST
            )

        return Response(UserSerializer(partner).data)


class AuthViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=RegisterSerializer,
        responses={201: UserSerializer},
    )
    @action(methods=["POST"], detail=False, url_path="register")
    def register(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            tokens = get_tokens_for_user(user)
            return Response(
                {"user": UserSerializer(user).data, "tokens": tokens},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        request=LoginSerializer,
        responses={200: UserSerializer},
    )
    @action(methods=["POST"], detail=False, url_path="login")
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            tokens = get_tokens_for_user(user)
            return Response(
                {"user": UserSerializer(user).data, "tokens": tokens},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        request=GoogleLoginSerializer,
        responses={
            200: OpenApiResponse(
                response=UserSerializer, description="Google login successful"
            ),
            400: OpenApiResponse(description="Invalid Google token"),
        },
    )
    @action(methods=["POST"], detail=False, url_path="google")
    def google_login(self, request):
        serializer = GoogleLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        id_token_str = serializer.validated_data["id_token"]

        try:
            # Verify token with Google
            id_info = id_token.verify_oauth2_token(id_token_str, requests.Request())

            email = id_info.get("email")
            display_name = id_info.get("name")
            firebase_uid = id_info.get("sub")  # unique Google account ID

            # Create or update user
            user, created = User.objects.get_or_create(email=email)
            if created:
                user.display_name = display_name
                user.firebase_uid = firebase_uid
                user.save()
            else:
                # Update firebase_uid if not already saved
                if not user.firebase_uid:
                    user.firebase_uid = firebase_uid
                    user.save(update_fields=["firebase_uid"])

            tokens = get_tokens_for_user(user)
            return Response(
                {"user": UserSerializer(user).data, "tokens": tokens},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        request=LogoutSerializer,
        responses={
            205: OpenApiResponse(response={"message": "Logged out successfully"})
        },
    )
    @action(methods=["POST"], detail=False, url_path="logout")
    def logout(self, request):
        serializer = LogoutSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        refresh_token = serializer.validated_data["refresh"]

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK,
            )
        except TokenError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
