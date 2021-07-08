public class Secret {
    public static void main(String[] args) {
        long i = 1;
        int count = 0;
        while(true){
            String strI = String.valueOf(i*7);

            if(strI.contains("7")){
                System.out.println(strI);
                count++;
            }
            if(count == 48){
                break;
            }
            i++;
        }
    }
    
}
