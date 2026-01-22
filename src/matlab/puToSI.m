function [R, L] = puToSI(Zpu, Zbase, f_grid)
% Convert per-unit impedance to SI units
Zsi = Zpu * Zbase;
R = real(Zsi);
L = imag(Zsi) / (2 * pi * f_grid);
end