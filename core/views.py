from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from core.models import Invite,PartnerLink,UserData
from core.serializers import UserDataSerializer, UserSerializer,RegisterSerializer,LoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth import get_user_model

User=get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }



class InvitationAndAcceptViewset(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

    @action(methods=["GET"], detail=False, url_path="create-invitation")
    def create_invitation(self, request):
        invite = Invite.objects.create(created_by=request.user)
        return Response(
            {"invite_code": str(invite.code)}, status=status.HTTP_201_CREATED
        )

    @action(methods=["POST"], detail=False, url_path="accept-invitation")
    def accept_invitation(self, request):
        code = request.data.get("invite_code")
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

        # Create mutual partner links
        PartnerLink.objects.create(user=request.user, partner=invite.created_by)
        PartnerLink.objects.create(user=invite.created_by, partner=request.user)

        invite.is_used = True
        invite.save()

        return Response({"message": "Linked successfully!"}, status=status.HTTP_200_OK)
    @action(methods=["DELETE"], detail=False, url_path="unlink")
    def unlink_partner(self, request):
        try:
            # Get current link
            link = PartnerLink.objects.get(user=request.user)
            partner = link.partner

            # Delete both sides of the link
            PartnerLink.objects.filter(user=request.user).delete()
            PartnerLink.objects.filter(user=partner).delete()

            return Response({"message": "Unlinked successfully!"}, status=status.HTTP_200_OK)

        except PartnerLink.DoesNotExist:
            return Response({"error": "No partner linked"}, status=status.HTTP_400_BAD_REQUEST)


class UserDataViewset(viewsets.ViewSet):
    @action(methods=["POST"], detail=False, url_path="update")
    def update_data(self, request):
        user_data, _ = UserData.objects.get_or_create(user=request.user)
        serializer = UserDataSerializer(user_data, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    @action(methods=["GET"], detail=False, url_path="partner-data")
    def partner_data(self, request):
        try:
            partner = request.user.user_link.partner
        except PartnerLink.DoesNotExist:
            return Response({"error": "No partner linked"}, status=status.HTTP_400_BAD_REQUEST)

        partner_data, _ = UserData.objects.get_or_create(user=partner)
        return Response(UserDataSerializer(partner_data).data)

    @action(methods=["GET"], detail=False, url_path="partner-info")
    def partner_info(self, request):
        try:
            partner = request.user.user_link.partner
        except PartnerLink.DoesNotExist:
            return Response({"error": "No partner linked"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(UserSerializer(partner).data)

class AuthViewSet(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]

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

    @action(methods=["POST"], detail=False, url_path="google")
    def google_login(self, request):
        id_token_str = request.data.get("id_token")
        try:
            
            id_info = id_token.verify_oauth2_token(id_token_str, requests.Request())

            email = id_info.get("email")
            display_name = id_info.get("name")

            user, created = User.objects.get_or_create(email=email)
            if created:
                user.display_name = display_name
                user.save()

            tokens = get_tokens_for_user(user)
            return Response(
                {"user": UserSerializer(user).data, "tokens": tokens},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    @action(methods=["POST"], detail=False, url_path="logout")
    def logout(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except KeyError:
            return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    