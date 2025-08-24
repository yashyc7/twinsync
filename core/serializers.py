# core/serializers.py
from rest_framework import serializers
from core.models import UserData, UserDataLogger
from django.contrib.auth import get_user_model, authenticate
from rest_framework import status
from rest_framework.response import Response
from django.utils import timezone
import base64

User = get_user_model()


class UserDataSerializer(serializers.ModelSerializer):
    updated_at = serializers.SerializerMethodField()
    shared_image=serializers.SerializerMethodField()

    class Meta:
        model = UserData
        fields = ["battery", "gps_lat", "gps_lon", "mood", "shared_image","updated_at"]

    def get_updated_at(self, obj):
        if obj.updated_at:
            dt = obj.updated_at
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return timezone.localtime(dt).strftime("%I:%M %p %d %B %Y").lstrip("0")
        return None
    
    
    def get_shared_image(self, obj):
        if obj.shared_image:
            encoded = base64.b64encode(obj.shared_image).decode("utf-8")
            return f"data:image/jpeg;base64,{encoded}"
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


class UserDataLoggerSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDataLogger
        fields = ["battery", "gps_lat", "gps_lon", "mood", "note", "logged_at"]


class UserResponseDataLoggerSerializer(serializers.ModelSerializer):
    logged_at = serializers.SerializerMethodField()

    class Meta:
        model = UserDataLogger
        fields = ["battery", "gps_lat", "gps_lon", "mood", "note", "logged_at"]

    def get_logged_at(self, obj):
        if obj.logged_at:
            dt = obj.logged_at
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            return timezone.localtime(dt).strftime("%I:%M %p %d %B %Y").lstrip("0")
        return None


class DailyUpdateRequestSerializer(serializers.Serializer):
    date = serializers.DateField()
