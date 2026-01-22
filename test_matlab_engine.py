import matlab.engine

eng = matlab.engine.start_matlab()
eng.eval("disp('✅ MATLAB is connected from PyCharm!')", nargout=0)
eng.quit()
