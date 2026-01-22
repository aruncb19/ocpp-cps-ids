% init_G2V.m
% -------------------------------
% 1) cd into your project folder
cd('C:\Users\arun0810\PyCharmProjects\ocpp-cps-project');

% 2) Simulation selection
sim_case   = 'G2V';
active_bus = 3;
plot_bus   = active_bus;
all_faults = {'1_1-2','1_1-3','2_1-2','2_2-3','3_1-3','3_2-3'};
fault_loc  = '1_1-2';
Ts         = 1e-5;

% 3) Determine FCT via the same switch-case as in main_v2gg2v.m
switch fault_loc
    case '1_1-2'
        switch sim_case
            case 'G2V'
                Ibat_ref = -200;
                if active_bus == 1
                    FCT = 0.082;
                elseif active_bus == 2
                    FCT = 0.238;
                elseif active_bus == 3
                    FCT = 0.238;
                else
                    FCT = 0.083;
                end
            otherwise
                error('Init script only supports G2V mode for now.');
        end
    otherwise
        error('Init script only supports fault_loc = ''1_1-2'' at this time.');
end

% 4) Fault timing
t_fault_start = 0.5;
t_fault_end   = t_fault_start + FCT;

% 5) Grid parameters
Sbase = 1e6;      Vbase = 345e3;  f_grid = 50; omega = 2*pi*f_grid;
Pm1 = 2.49; Pm2 = 4.21; Pm3 = 8.20;
H1 = 10;  H2 = 15;  H3 = 60;  D = 20;
E1 = 1.07364213042869;  E2 = 1.05726676017896;  E3 = 1.05298913370226;
S1pu = (1.5 + .45j);  S2pu = (1.0 + .3j);  S3pu = (12.4 + 2.5j);
Z12pu = .46j;  Z13pu = .26j;  Z23pu = .0806j;
Zbase = Vbase^2/Sbase;
[R12, L12] = puToSI(Z12pu, Zbase, f_grid);
[R13, L13] = puToSI(Z13pu, Zbase, f_grid);
[R23, L23] = puToSI(Z23pu, Zbase, f_grid);

% 6) V2G/G2V parameters
Snom_trafo = 1050e6;
Linv    = 1/10*0.48e-3;
Lgrid   = 1/10*0.69e-3;
Rd      = 1.31;
Cf      = 10*165e-6;
C_Vdc   = 100*18e-3;  V0_Vdc = 1.5e3;
Lbat    = 2e-3;
Batt_Vnom      = 400;  Batt_Ah       = 35;
Batt_InitSOC   = 80;   Batt_RespTime = 2;
Kp_PLL = 100;  Ki_PLL = 10000;
f_SW   = 5000;
Vdc_ref = 1.5e3;  Kp_outer = 250;  Ki_outer = 10000;
Kp_inner = 100;   Ki_inner = 5000;
Kp_CC = 10;  Ki_CC = 1;  UpSat_CC = 1;  LowSat_CC = 0;

% 7) Finally, open the Simulink model (but don’t simulate yet)
open_system('G2V');