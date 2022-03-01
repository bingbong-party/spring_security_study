package userauth;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import java.util.Date;

@Slf4j
public class TokenProvider {

    // @Slf4j랑 동시에 사용이 불가하네..!? (빌드가 안 됨)
//    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    private static final String JWT_SECRET = "secretkey";

    // 토큰 유효시간
    private static final int JWT_EXPIRATION_MS = 604800000;

    // jwt토큰 생성
    public static String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION_MS);

        return Jwts.builder()
                .setSubject((String) authentication.getPrincipal())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }

    // 토큰에서 아이디 추출
    public static String getUserIdFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(JWT_SECRET) // jws서명 검증을 위한 secret key 혹은 비대징 public key를 지정한다
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    // 토큰의 유효성 검사
    public static boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            log.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty.");
        }
        return false;
    }
}
