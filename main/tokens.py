from rest_framework_simplejwt.tokens import RefreshToken as SimpleJWTRefreshToken

class CustomRefreshToken(SimpleJWTRefreshToken):
    def __init__(self, token=None, verify=False):
        super().__init__(token, verify)

    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        # Customize payload here to include userId as UUID
        token.payload['user_id'] = str(user.userId)
        return token
