# core/serializers.py
from rest_framework import serializers
from core.models import UserData
from django.contrib.auth import get_user_model, authenticate
from rest_framework import status
from rest_framework.response import Response

User = get_user_model()


class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserData
        fields = ["battery", "steps", "gps_lat", "gps_lon", "mood", "updated_at"]


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "display_name", "firebase_uid"]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "password", "display_name"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(password=password, **validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(email=data["email"], password=data["password"])
        if not user:
            return Response(
                {"error": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )
        return user


class GoogleLoginSerializer(serializers.Serializer):
    id_token = serializers.CharField()


class AcceptInvitationSerializer(serializers.Serializer):
    invite_code = serializers.CharField()


class LogoutSerializer(serializers.Serializer):
    refresh=serializers.CharField()