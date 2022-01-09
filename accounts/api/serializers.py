from rest_framework import serializers

from accounts.models import User


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'name',)
        write_only_fields = ('password',)
        read_only_fields = ('id',)

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            name=validated_data['name'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate_username(self, value):
        if not User.objects.filter(username=value).exists():
            raise serializers.ValidationError('invalid credentials')
        return value


class ResetPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(write_only=True)

    def validate_username(self, value):
        if not User.objects.filter(username=value).exists():
            raise serializers.ValidationError('no account fount for this username')
        return value


class ResetPasswordTokenSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)
    uid = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'name',)
