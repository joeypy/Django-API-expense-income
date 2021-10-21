from django.contrib.auth import get_user_model

from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    def validate(self, attr):
        email = attr.get('email', '')
        username = attr.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('The username should only contain alphanumeric characters')
        return attr

    def create(self, validate_data):
        return User.objects.create_user(**validate_data)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['token']