# core/serializers.py
from rest_framework import serializers
from core.models import UserData
from django.contrib.auth import get_user_model, authenticate
from rest_framework import status
from rest_framework.response import Response
from django.utils import timezone

User = get_user_model()


class UserDataSerializer(serializers.ModelSerializer):
    updated_at = serializers.SerializerMethodField()

    class Meta:
        model = UserData
        fields = ["battery", "gps_lat", "gps_lon", "mood", "updated_at"]

    def get_updated_at(self, obj):
        if obj.updated_at:
            dt = obj.updated_at
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return timezone.localtime(dt).strftime("%I:%M %p %d %B %Y").lstrip("0")
        return None


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
    refresh = serializers.CharField()
