package userauth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@EnableWebSecurity //웹 보안 활성화를 위한 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    private final JwtAuthenticationEntryPoint unauthorizedHandler;

    // 스프링 시큐리티 앞단 설정들을 할 수 있다
    @Override
    public void configure(WebSecurity web) throws Exception {
        /**
         * resource모든 접근을 허용하는 설정을 해버리면
         * HttpSecurity 설정한 ADIM권한을 가진 사용자만 resources 접근 가능한 설정을 무시해버린다.
         */
        web.ignoring()
                .antMatchers("/resources/**");
    }

    // 스프링 시큐리티의 설정을 할 수 있다.
    @Override
    public void configure(HttpSecurity http) throws Exception {
        /*
        리소스(URL)의 접근 권한 설정
        : 특정 리소스의 접근 허용 또는 특정 권한을 가진 사용자에게만 접근을 허용할 수 있다.

        - antMatchers : 특정 리소스에 대해 권한 설정
        - permitAll : antMatchers 설정한 리소스의 접근을 인증절차 없이 허용
        - hasAnyRole : 리소스 admin으로 시작하는 모든 URL은 인증 후 ADMIN레벨의 권한을 가진 사용자만 접근 허용
        - any Request : permitAll, hasAnyRole 설정한 리소스 외의 나머지들은 무조건 인증을 완료해야 접근 가능
         */
        http
                .cors()
            .and()
                .csrf()
                .disable()
                .exceptionHandling()
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint()) // 이전 프로젝트 참고
            .and()
                .sessionManagement() //JWT를 쓰려면 Spring Security에서 기본적으로 지원하는 Session 설정을 해제해야 한다.
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .authorizeRequests()
                .antMatchers("/login**").permitAll()
                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                .antMatchers("/order/**").hasAnyRole("USER")
                .anyRequest().authenticated()
            .and()

        /*
        formLogin
        : 로그인 페이지와 기타 로그인 처리 및 성공 실패 처리를 설정
        http.formLogin() 를 호출하지 않으면 완전히 로그인처리 커스텀필터를 만들고 설정하지 않는 이상
        로그인 페이지 및 기타처리를 할 수 가 없습니다. 커스텀 필터를 만들면 사실상 필요 없는 경우도 있습니다.

        - loginPage : 사용자가 따로 만든 로그인 페이지를 사용하려고 할 때 설정. 기본 URL은 "/login"이다.
        - loginProcessingUrl : 로그인(인증처리)을 하는 URL설정 "login-process"가 호출되면 인증처리를 수행하는 필터 호출됨
          즉, UsernamePasswordAuthenticationFilter가 실행된다
        - defaultSuccessUrl : 정상정으로 인증 성공했을 경우 이동하는 페이지. 기본 URL은 "/"이다.
        - successHandler : 정상 인증 후 별도의 처리가 필요한 경우 커스텀 핸들러를 생성하여 등록할 수 있다.
          커스텀 핸들러를 생성하여 등록하면 인증성공 후 사용자가 추가한 로직을 수행하고 성공 페이지로 이동한다.
          아래의 경우 내부에서 익명클래스로 선언하였음
        - failureUrl : 인증 실패할 경우 이동할 페이지
        - failureHandler : 인증 실패 후 별도의 처리가 필요한경우 커스텀 핸들러를 생성하여 등록할 수 있습니다.
          아래의 경우 내부에서 익명클래스로 선언하였음
         */
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("login-process")
                .defaultSuccessUrl("/main")
                .usernameParameter("username") // 아이디 파라미터명 설정
                .passwordParameter("password") //패스워드 파라미터명 설정
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                                        HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                }) // 익명 내부 클래스덕분에, 자식 클래스를 생성하지 않아도 부모 클래스를 상속받은 객체를 사용할 수 있다.
                .failureUrl("login-fail")
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest,
                                                        HttpServletResponse response,
                                                        AuthenticationException e) throws IOException, ServletException {
                        System.out.println("authentication : " + e.getMessage());
                        response.sendRedirect("login");
                    }
                });

//        지정된 필터 앞에 커스텀 필터를 추가 (UsernamePasswordAuthenticationFilter 보다 먼저 실행된다)
//        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

    }

    //비밀번호 암호화를 위한 Encoder 설정
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
