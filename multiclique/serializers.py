from rest_framework import serializers

POLICIY_PRESETS = (("ELIO_DAO", "Elio Dao Presets"),)


class InstallAccountAndPolicySerializer(serializers.Serializer):
    source = serializers.CharField(max_length=56)
    policy_preset = serializers.ChoiceField(choices=POLICIY_PRESETS)


class AccountSerializer(serializers.Serializer):
    public_keys = serializers.ListField(child=serializers.CharField(max_length=56))
    default_threshold = serializers.IntegerField(min_value=1)
    policy_preset = serializers.ChoiceField(choices=[("ELIO_DAO", "Elio Dao Presets")])
    dao = serializers.CharField(max_length=16)
